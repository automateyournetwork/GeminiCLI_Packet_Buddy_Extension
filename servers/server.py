#!/usr/bin/env python3
import os, base64, json, shutil, tempfile, asyncio, subprocess
from typing import Any
from fastmcp import FastMCP
from dotenv import load_dotenv
from google import genai
from google.genai import types

# =====================================================================
# INIT
# =====================================================================
load_dotenv()
client = genai.Client()
mcp = FastMCP("PacketCopilot_FileSearch")

DEFAULT_DROP_KEYS = {
    "data.data",
    "tcp.payload",
    "tls.app_data",
    "http.file_data",
    "usb.capdata",
    "data.text",
}

# =====================================================================
# TOKENIZER (for TOON token savings)
# =====================================================================
try:
    import tiktoken
    tokenizer = tiktoken.get_encoding("o200k_base")
except Exception:
    tokenizer = None

def count_tokens(text: str) -> int:
    if tokenizer is None:
        return -1
    try:
        return len(tokenizer.encode(text))
    except Exception:
        return -1


# =====================================================================
# SAFE JSON NORMALIZATION (for TOON)
# =====================================================================
def make_json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    else:
        return obj


# =====================================================================
# TOON CONVERSION FUNCTION
# =====================================================================
def toon_with_stats(pyats_json: Any) -> tuple[str, str]:
    """
    Input: parsed JSON from tshark (sanitized)
    Returns:
      toon_text (string)
      stats_report (string)
    """
    safe = make_json_safe(pyats_json)
    json_str = json.dumps(safe, indent=2)

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f_json:
        f_json.write(json_str)
        f_json.flush()
        src = f_json.name
        dst = f_json.name + ".toon"

    cmd = ["npx", "@toon-format/cli", src, "-o", dst]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"TOON CLI failed:\n{result.stderr}")

    toon_text = open(dst).read()

    # token savings
    j_tokens = count_tokens(json_str)
    t_tokens = count_tokens(toon_text)

    if j_tokens > 0 and t_tokens > 0:
        reduction = 100 * (1 - (t_tokens / j_tokens))
        stats = (
            "=== TOKEN SAVINGS ===\n"
            f"JSON tokens: {j_tokens}\n"
            f"TOON tokens: {t_tokens}\n"
            f"Saved: {reduction:.1f}%\n"
        )
    else:
        stats = "=== TOKEN SAVINGS ===\n(unavailable)\n"

    return toon_text, stats


# =====================================================================
# PCAP HEX/PAYLOAD SANITIZER
# =====================================================================
def _looks_like_big_hex(val: Any, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    v = val.replace(":", "").replace(" ", "").lower()
    return len(v) >= min_len and all(c in "0123456789abcdef" for c in v)

def _sanitize_layers(obj: Any, drop_keys: set[str], aggressive: bool, hex_len_cutoff: int):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            # Drop heavy or unwanted keys
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



# =====================================================================
# 1️⃣ PCAP → JSON
# =====================================================================
@mcp.tool
async def convert_to_json(filename: str = "", data_b64: str = "") -> str:
    """Convert .pcap to JSON using tshark asynchronously."""
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

    proc = await asyncio.create_subprocess_exec(
        "tshark", "-nlr", pcap_path, "-T", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        if b"pcapng" in stderr.lower():
            # convert first
            fixed = pcap_path + ".fixed"
            await asyncio.create_subprocess_exec("editcap", "-F", "libpcap", pcap_path, fixed)
            proc2 = await asyncio.create_subprocess_exec(
                "tshark", "-nlr", fixed, "-T", "json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc2.communicate()
            if proc2.returncode != 0:
                raise RuntimeError(stderr.decode())
        else:
            raise RuntimeError(stderr.decode())

    with open(json_path, "w") as f:
        f.write(stdout.decode())

    return json_path



# =====================================================================
# 2️⃣ SANITIZE JSON
# =====================================================================
@mcp.tool
async def sanitize_json(json_path: str,
                        extra_drop_keys: list[str] | None = None,
                        aggressive: bool = False,
                        hex_len_cutoff: int = 256) -> str:
    """Remove large payloads and hex blobs before indexing."""
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

    out_path = json_path.replace(".json", f".sanitized.{int(asyncio.get_event_loop().time())}.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    return out_path



# =====================================================================
# 2B️⃣ SANITIZE → TOON
# =====================================================================
@mcp.tool
async def sanitize_and_toon(json_path: str,
                            extra_drop_keys: list[str] | None = None,
                            aggressive: bool = False,
                            hex_len_cutoff: int = 256) -> dict:
    """
    Sanitize tshark JSON AND convert to TOON.
    Returns:
      {
        "toon_path": "...",
        "stats": "token savings report"
      }
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

    toon_text, stats = toon_with_stats(data)

    toon_path = json_path.replace(".json", ".toon.txt")
    with open(toon_path, "w") as f:
        f.write(toon_text)

    return {"toon_path": toon_path, "stats": stats}



# =====================================================================
# 3️⃣ UPLOAD FOR JSON
# =====================================================================
@mcp.tool
async def upload_and_index(json_path: str) -> str:
    """Upload sanitized JSON to Gemini File Search asynchronously."""
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"{json_path} not found")

    store = client.file_search_stores.create(
        config={"display_name": f"pcap_store_{int(asyncio.get_event_loop().time())}"}
    )
    store_name = store.name
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

    op_name = op.name
    for _ in range(60):
        current = client.operations.get(op_name)
        if getattr(current, "done", False):
            break
        await asyncio.sleep(2)

    return store_name



# =====================================================================
# 3B️⃣ UPLOAD FOR TOON
# =====================================================================
@mcp.tool
async def upload_and_index_toon(toon_path: str) -> str:
    """Upload TOON file to Gemini File Search."""
    if not os.path.exists(toon_path):
        raise FileNotFoundError(f"{toon_path} not found")

    store = client.file_search_stores.create(
        config={"display_name": f"toon_store_{int(asyncio.get_event_loop().time())}"}
    )
    store_name = store.name
    print(f"🪣 Using FileSearchStore name: {store_name}")

    op = client.file_search_stores.upload_to_file_search_store(
        file_search_store_name=store_name,
        file=toon_path,
        config={
            "display_name": os.path.basename(toon_path),
            "mime_type": "text/plain",
        },
    )

    op_name = op.name
    for _ in range(60):
        current = client.operations.get(op_name)
        if getattr(current, "done", False):
            break
        await asyncio.sleep(2)

    return store_name



# =====================================================================
# 4️⃣ ANALYZE JSON RAG
# =====================================================================
@mcp.tool
async def analyze_pcap(store_name: str, question: str) -> dict:
    """Analyze sanitized JSON using Gemini File Search."""
    if not store_name:
        raise ValueError("Missing File Search store name.")
    if not question:
        raise ValueError("Missing analysis question.")

    loop = asyncio.get_event_loop()
    resp = await loop.run_in_executor(
        None,
        lambda: client.models.generate_content(
            model="gemini-2.5-flash",
            contents=question,
            config=types.GenerateContentConfig(
                tools=[
                    types.Tool(
                        file_search=types.FileSearch(file_search_store_names=[store_name])
                    )
                ]
            ),
        ),
    )

    grounding = getattr(resp.candidates[0], "grounding_metadata", None)
    sources = []
    if grounding and getattr(grounding, "grounding_chunks", None):
        sources = [c.retrieved_context.title for c in grounding.grounding_chunks]

    return {"answer": resp.text, "sources": sources, "store": store_name}



# =====================================================================
# 4B️⃣ ANALYZE TOON RAG
# =====================================================================
@mcp.tool
async def analyze_toon(store_name: str, question: str) -> dict:
    """Analyze TOON-formatted PCAP data with Gemini."""
    if not store_name:
        raise ValueError("Missing File Search store name.")
    if not question:
        raise ValueError("Missing analysis question.")

    loop = asyncio.get_event_loop()
    resp = await loop.run_in_executor(
        None,
        lambda: client.models.generate_content(
            model="gemini-2.5-flash",
            contents=question,
            config=types.GenerateContentConfig(
                tools=[
                    types.Tool(
                        file_search=types.FileSearch(file_search_store_names=[store_name])
                    )
                ]
            ),
        ),
    )

    grounding = getattr(resp.candidates[0], "grounding_metadata", None)
    sources = []
    if grounding and getattr(grounding, "grounding_chunks", None):
        sources = [c.retrieved_context.title for c in grounding.grounding_chunks]

    return {"answer": resp.text, "sources": sources}



# =====================================================================
# RUN MCP SERVER
# =====================================================================
if __name__ == "__main__":
    mcp.run()
