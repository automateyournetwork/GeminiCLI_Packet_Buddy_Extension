#!/usr/bin/env python3
import os, base64, subprocess, tempfile, time, shutil
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

# ──────────────────────────────────────────────
# 1️⃣ Convert PCAP → JSON (robust)
# ──────────────────────────────────────────────
@mcp.tool
def convert_to_json(session_id: str, filename: str = "", data_b64: str = "") -> str:
    """
    Convert a .pcap to JSON using tshark. Accepts either a local file or base64 data.
    """
    s = _session(session_id)

    # prefer direct file if it exists
    if filename and os.path.exists(filename):
        pcap_path = filename
    else:
        if not data_b64:
            raise ValueError("Must supply either a valid filename or data_b64.")
        pcap_path = os.path.join(s["dir"], filename or "capture.pcap")
        with open(pcap_path, "wb") as f:
            f.write(base64.b64decode(data_b64))

    json_path = os.path.join(s["dir"], os.path.basename(pcap_path) + ".json")

    result = subprocess.run(
        ["tshark", "-nlr", pcap_path, "-T", "json"],
        capture_output=True,
        text=True
    )

    # fallback: convert from pcapng → libpcap if needed
    if result.returncode != 0:
        if "pcapng" in result.stderr:
            fixed_path = pcap_path + ".fixed"
            subprocess.run(["editcap", "-F", "libpcap", pcap_path, fixed_path], check=True)
            result = subprocess.run(["tshark", "-nlr", fixed_path, "-T", "json"],
                                    capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")

    with open(json_path, "w") as f:
        f.write(result.stdout)

    s["pcap_path"], s["json_path"] = pcap_path, json_path
    return json_path

# ──────────────────────────────────────────────
# 2️⃣ Upload JSON to Gemini File Search
# ──────────────────────────────────────────────
@mcp.tool
def upload_and_index(session_id: str) -> str:
    """Upload JSON to Gemini File Search and wait for indexing."""
    s = _session(session_id)
    json_path = s.get("json_path")
    if not json_path or not os.path.exists(json_path):
        raise ValueError("No JSON found. Run convert_to_json first.")

    # Create or get the store
    store = client.file_search_stores.create(
        config={"display_name": f"pcap_store_{session_id}"}
    )

    # Handle both SDK return types
    if isinstance(store, str):
        store_name = store
    elif hasattr(store, "name"):
        store_name = store.name
    elif isinstance(store, dict) and "name" in store:
        store_name = store["name"]
    else:
        raise TypeError(f"Unexpected store return type: {type(store)}")

    # Upload file to File Search store
    op = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=json_path,
        config={"display_name": os.path.basename(json_path)},
    )

    # Poll until indexing is complete
    while not getattr(op, "done", False):
        time.sleep(2)
        op = client.operations.get(op.name)

    s["store_name"] = store_name
    return f"✅ Uploaded and indexed {json_path} to Gemini File Search store: {store_name}"

# ──────────────────────────────────────────────
# 3️⃣ Ask a grounded question
# ──────────────────────────────────────────────
@mcp.tool
def analyze_pcap(session_id: str, question: str) -> dict:
    s = _session(session_id)
    store_name = s.get("store_name")
    if not store_name:
        raise ValueError("Run upload_and_index first.")

    resp = client.models.generate_content(
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

    grounding = getattr(resp.candidates[0], "grounding_metadata", None)
    sources = []
    if grounding and grounding.grounding_chunks:
        sources = [c.retrieved_context.title for c in grounding.grounding_chunks]

    return {
        "answer": resp.text,
        "sources": sources,
        "meta": {"store": store_name}
    }

# ──────────────────────────────────────────────
# 4️⃣ Cleanup
# ──────────────────────────────────────────────
@mcp.tool
def cleanup(session_id: str) -> str:
    s = SESSIONS.pop(session_id, None)
    if s and (d := s.get("dir")) and os.path.exists(d):
        shutil.rmtree(d, ignore_errors=True)
    return "ok"

if __name__ == "__main__":
    mcp.run()
