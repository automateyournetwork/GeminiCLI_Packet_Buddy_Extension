#!/usr/bin/env python3
import os, base64, subprocess, tempfile, time, json, shutil
from typing import Any
from fastmcp import FastMCP
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client()
mcp = FastMCP("PacketCopilot_FileSearch")

# Default fields to drop during sanitization (payloads, binary blobs, etc.)
DEFAULT_DROP_KEYS = {
    "data.data",
    "tcp.payload",
    "tls.app_data",
    "http.file_data",
    "usb.capdata",
    "data.text",
}

# ──────────────────────────────────────────────
# Utility: detect long hex/binary strings
# ──────────────────────────────────────────────
def _looks_like_big_hex(val: Any, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    v = val.replace(":", "").replace(" ", "").lower()
    return len(v) >= min_len and all(c in "0123456789abcdef" for c in v)

# Recursive sanitization
def _sanitize_layers(obj: Any, drop_keys: set[str], aggressive: bool, hex_len_cutoff: int):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            # Drop keys by name or dotted suffix
            if k in drop_keys or any(k.endswith(f".{suf}") for suf in drop_keys):
                obj.pop(k, None)
                continue
            v = obj.get(k)
            if isinstance(v, (dict, list)):
                _sanitize_layers(v, drop_keys, aggressive, hex_len_cutoff)
            elif aggressive and _looks_like_big_hex(v, hex_len_cutoff):
                obj.pop(k, None)
    elif isinstance(obj, list):
        for item in obj:
            _sanitize_layers(item, drop_keys, aggressive, hex_len_cutoff)


# ──────────────────────────────────────────────
# 1️⃣ Convert PCAP → JSON
# ──────────────────────────────────────────────
@mcp.tool
def convert_to_json(filename: str = "", data_b64: str = "") -> str:
    """
    Convert a .pcap to JSON using tshark.
    Accepts either a local filename or base64-encoded data.
    Returns the JSON file path.
    """
    if not filename and not data_b64:
        raise ValueError("Must supply either filename or base64 data.")

    workdir = tempfile.mkdtemp(prefix="pcap_")
    pcap_path = os.path.join(workdir, os.path.basename(filename or "capture.pcap"))
    json_path = pcap_path + ".json"

    if data_b64:
        with open(pcap_path, "wb") as f:
            f.write(base64.b64decode(data_b64))
    elif os.path.exists(filename):
        shutil.copy(filename, pcap_path)
    else:
        raise FileNotFoundError(f"{filename} not found")

    result = subprocess.run(["tshark", "-nlr", pcap_path, "-T", "json"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        if "pcapng" in result.stderr.lower():
            fixed = pcap_path + ".fixed"
            subprocess.run(["editcap", "-F", "libpcap", pcap_path, fixed], check=True)
            result = subprocess.run(["tshark", "-nlr", fixed, "-T", "json"],
                                    capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"tshark failed: {result.stderr}")

    with open(json_path, "w") as f:
        f.write(result.stdout)

    return json_path


# ──────────────────────────────────────────────
# 2️⃣ Sanitize JSON before upload
# ──────────────────────────────────────────────
@mcp.tool
def sanitize_json(json_path: str,
                  extra_drop_keys: list[str] | None = None,
                  aggressive: bool = False,
                  hex_len_cutoff: int = 256) -> str:
    """
    Strip large payloads and sensitive binary blobs from JSON before indexing.
    Returns the sanitized JSON file path.
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"{json_path} not found")

    with open(json_path, "r") as f:
        data = json.load(f)

    drops = set(DEFAULT_DROP_KEYS)
    if extra_drop_keys:
        drops.update(extra_drop_keys)

    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})
        _sanitize_layers(layers, drops, aggressive, hex_len_cutoff)

    out_path = json_path.replace(".json", f".sanitized.{int(time.time())}.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    return out_path


# ──────────────────────────────────────────────
# 3️⃣ Upload sanitized JSON → Gemini File Search
# ──────────────────────────────────────────────
@mcp.tool
def upload_and_index(json_path: str) -> str:
    """
    Upload the given JSON to Gemini File Search.
    Returns the File Search store name.
    """
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"{json_path} not found")

    store = client.file_search_stores.create(
        config={"display_name": f"pcap_store_{int(time.time())}"}
    )
    store_name = getattr(store, "name", str(store))

    print(f"🪣 Using FileSearchStore name: {store_name}")

    op = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=json_path,
        config={
            "display_name": os.path.basename(json_path),
            "mime_type": "text/plain",
            "chunking_config": {
                "white_space_config": {
                    "max_tokens_per_chunk": 500,
                    "max_overlap_tokens": 100,
                }
            },
        },
    )

    op_name = getattr(op, "name", str(op))
    for _ in range(60):
        try:
            status = client.operations.get(op_name)
            if getattr(status, "done", False) or (
                isinstance(status, dict) and status.get("done")
            ):
                break
        except Exception as e:
            print(f"⚠️ Polling error: {e}")
        time.sleep(2)

    return store_name


# ──────────────────────────────────────────────
# 4️⃣ Analyze via Gemini File Search
# ──────────────────────────────────────────────
@mcp.tool
def analyze_pcap(store_name: str, question: str) -> dict:
    """
    Use Gemini 2.5 Flash with File Search to analyze the capture.
    """
    if not store_name:
        raise ValueError("Missing File Search store name.")
    if not question:
        raise ValueError("Missing analysis question.")

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

    return {"answer": resp.text, "sources": sources, "store": store_name}


if __name__ == "__main__":
    mcp.run()
