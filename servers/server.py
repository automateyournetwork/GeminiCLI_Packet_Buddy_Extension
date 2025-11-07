#!/usr/bin/env python3
import os, json, base64, subprocess, tempfile, time, uuid, shutil
from collections import defaultdict
from fastmcp import FastMCP
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()
mcp = FastMCP("PacketCopilot_FileSearch")

SESSIONS = defaultdict(dict)

def _session(session_id: str):
    s = SESSIONS[session_id]
    if "dir" not in s:
        s["dir"] = tempfile.mkdtemp(prefix=f"pcap_{session_id}_")
    return s

# ──────────────────────────────────────────────────────────────
# 1️⃣  Convert PCAP → JSON with tshark
# ──────────────────────────────────────────────────────────────
@mcp.tool
def convert_to_json(session_id: str, filename: str, data_b64: str) -> str:
    """
    Decode base64 PCAP, run tshark to JSON (stdout capture, no shell redirection).
    """
    import base64, os, subprocess, time

    s = _session(session_id)
    pcap_path = os.path.join(s["dir"], filename)
    json_path = pcap_path + ".json"

    # 1️⃣ Write the uploaded pcap file
    with open(pcap_path, "wb") as f:
        f.write(base64.b64decode(data_b64))

    # 2️⃣ Run tshark safely (capture stdout/stderr)
    result = subprocess.run(
        ["tshark", "-nlr", pcap_path, "-T", "json"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        errpath = json_path + ".err"
        with open(errpath, "w") as ef:
            ef.write(result.stderr or "<no stderr>")
        raise RuntimeError(
            f"tshark failed with exit {result.returncode}. See {errpath}\n{result.stderr}"
        )

    # 3️⃣ Write JSON output
    with open(json_path, "w") as jf:
        jf.write(result.stdout)

    # 4️⃣ Update session
    s["pcap_path"] = pcap_path
    s["json_path"] = json_path
    s.setdefault("created_at", time.time())
    return json_path

# ──────────────────────────────────────────────────────────────
# 2️⃣  Upload JSON to Gemini File Search
# ──────────────────────────────────────────────────────────────
@mcp.tool
def upload_and_index(session_id: str) -> str:
    """Upload JSON to Gemini File Search and wait for indexing."""
    s = _session(session_id)
    json_path = s.get("json_path")
    if not json_path or not os.path.exists(json_path):
        raise ValueError("No JSON found. Run convert_to_json first.")

    store = client.file_search_stores.create(
        config={"display_name": f"pcap_store_{session_id}"}
    )

    op = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store.name,
        file=json_path,
        config={"display_name": os.path.basename(json_path)}
    )

    while not op.done:
        time.sleep(5)
        op = client.operations.get(op.name)

    s["store_name"] = store.name
    return f"✅ Indexed {json_path} into File Search store {store.name}"

# ──────────────────────────────────────────────────────────────
# 3️⃣  Ask a grounded question
# ──────────────────────────────────────────────────────────────
@mcp.tool
def analyze_pcap(session_id: str, question: str) -> dict:
    """Ask Gemini 2.5 Flash a question grounded on the uploaded JSON."""
    s = _session(session_id)
    store_name = s.get("store_name")
    if not store_name:
        raise ValueError("Run upload_and_index first.")

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=question,
        config=types.GenerateContentConfig(
            tools=[types.Tool(
                file_search=types.FileSearch(
                    file_search_store_names=[store_name]
                )
            )]
        )
    )

    # pull citations
    grounding = response.candidates[0].grounding_metadata
    sources = {c.retrieved_context.title for c in grounding.grounding_chunks}

    return {
        "answer": response.text,
        "sources": list(sources),
        "meta": {"store": store_name}
    }

# ──────────────────────────────────────────────────────────────
# 4️⃣  Cleanup temp files
# ──────────────────────────────────────────────────────────────
@mcp.tool
def cleanup(session_id: str) -> str:
    s = SESSIONS.pop(session_id, None)
    if s and (d := s.get("dir")) and os.path.exists(d):
        shutil.rmtree(d, ignore_errors=True)
    return "ok"

# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
