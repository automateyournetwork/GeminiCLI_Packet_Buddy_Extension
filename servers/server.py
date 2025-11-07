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
    """Create or retrieve session scratch directory."""
    s = SESSIONS[session_id]
    if "dir" not in s:
        s["dir"] = tempfile.mkdtemp(prefix=f"pcap_{session_id}_")
    return s


# ──────────────────────────────────────────────
# 1️⃣ Convert PCAP → JSON (robust)
# ──────────────────────────────────────────────
@mcp.tool
def convert_to_json(session_id: str, filename: str = "", data_b64: str = "") -> str:
    """Convert a .pcap to JSON using tshark. Accepts either a local file or base64 data."""
    s = _session(session_id)

    # Write PCAP to temp if base64 provided
    if filename and os.path.exists(filename):
        pcap_path = filename
    else:
        if not data_b64:
            raise ValueError("Must supply either a valid filename or data_b64.")
        pcap_path = os.path.join(s["dir"], filename or "capture.pcap")
        with open(pcap_path, "wb") as f:
            f.write(base64.b64decode(data_b64))

    json_path = os.path.join(s["dir"], os.path.basename(pcap_path) + ".json")

    # Convert using tshark
    result = subprocess.run(
        ["tshark", "-nlr", pcap_path, "-T", "json"],
        capture_output=True, text=True
    )

    # fallback for pcapng
    if result.returncode != 0:
        if "pcapng" in result.stderr.lower():
            fixed = pcap_path + ".fixed"
            subprocess.run(["editcap", "-F", "libpcap", pcap_path, fixed], check=True)
            result = subprocess.run(
                ["tshark", "-nlr", fixed, "-T", "json"],
                capture_output=True, text=True
            )
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")

    with open(json_path, "w") as f:
        f.write(result.stdout)

    s["pcap_path"], s["json_path"] = pcap_path, json_path
    return json_path


# ──────────────────────────────────────────────
# 2️⃣ Upload JSON → Gemini File Search
# ──────────────────────────────────────────────
@mcp.tool
def upload_and_index(session_id: str) -> str:
    """Upload JSON to Gemini File Search deterministically (SDK v1.47-safe)."""
    s = _session(session_id)
    json_path = s.get("json_path")
    if not json_path or not os.path.exists(json_path):
        raise ValueError("No JSON found. Run convert_to_json first.")

    # ── 1️⃣  Create File Search Store ───────────────────────────────────────
    store_obj = client.file_search_stores.create(
        config={"display_name": f"pcap_store_{session_id}"}
    )

    # Normalize possible return types (SDK version safe)
    if hasattr(store_obj, "name"):
        store_name = store_obj.name
    elif isinstance(store_obj, dict) and "name" in store_obj:
        store_name = store_obj["name"]
    elif isinstance(store_obj, str):
        store_name = store_obj
    else:
        raise TypeError(f"Unexpected store object: {store_obj}")

    # ── 2️⃣  Upload file ────────────────────────────────────────────────────
    op = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=json_path,
        config={
            "display_name": os.path.basename(json_path),
            "mime_type": "application/json",
            "chunking_config": {
                "white_space_config": {
                    "max_tokens_per_chunk": 500,
                    "max_overlap_tokens": 100,
                }
            },
        },
    )

    # ── 3️⃣  Poll until indexing completes ─────────────────────────────────
    op_name = getattr(op, "name", op if isinstance(op, str) else str(op))
    for _ in range(60):  # ~2 minutes
        current = client.operations.get(op_name)
        if getattr(current, "done", False) or (
            isinstance(current, dict) and current.get("done")
        ):
            break
        time.sleep(2)

    s["store_name"] = store_name
    return f"✅ Uploaded and indexed {json_path} to Gemini File Search store: {store_name}"


# ──────────────────────────────────────────────
# 3️⃣ Analyze → Gemini 2.5 Flash
# ──────────────────────────────────────────────
@mcp.tool
def analyze_pcap(session_id: str, question: str) -> dict:
    """Ask Gemini 2.5 Flash a grounded question on the indexed JSON."""
    s = _session(session_id)
    store_name = s.get("store_name")
    if not store_name:
        raise ValueError("Run upload_and_index first.")

    resp = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=question,
        config=types.GenerateContentConfig(
            tools=[
                types.Tool(
                    file_search=types.FileSearch(
                        file_search_store_names=[store_name]
                    )
                )
            ]
        ),
    )

    grounding = getattr(resp.candidates[0], "grounding_metadata", None)
    sources = []
    if grounding and getattr(grounding, "grounding_chunks", None):
        sources = [c.retrieved_context.title for c in grounding.grounding_chunks]

    return {"answer": resp.text, "sources": sources, "meta": {"store": store_name}}


# ──────────────────────────────────────────────
# 4️⃣ Cleanup
# ──────────────────────────────────────────────
@mcp.tool
def cleanup(session_id: str) -> str:
    """Delete temp directory and remove session from cache."""
    s = SESSIONS.pop(session_id, None)
    if s and (d := s.get("dir")) and os.path.exists(d):
        shutil.rmtree(d, ignore_errors=True)
    return "ok"


if __name__ == "__main__":
    mcp.run()
