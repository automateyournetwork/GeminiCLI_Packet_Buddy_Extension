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
mcp = FastMCP("PacketBuddy")

DEFAULT_DROP_KEYS = {
    "data.data",
    "tcp.payload",
    "tls.app_data",
    "http.file_data",
    "usb.capdata",
    "data.text",
}

# =====================================================================
# TOKENIZER
# =====================================================================
try:
    import tiktoken
    tokenizer = tiktoken.get_encoding("o200k_base")
except:
    tokenizer = None

def count_tokens(text: str) -> int:
    if not tokenizer:
        return -1
    try:
        return len(tokenizer.encode(text))
    except:
        return -1

# =====================================================================
# JSON SAFE
# =====================================================================
def make_json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    return obj

# =====================================================================
# TOON CONVERTER
# =====================================================================
def toon_with_stats(pyats_json: Any) -> tuple[str, str]:
    safe = make_json_safe(pyats_json)
    json_str = json.dumps(safe, indent=2)

    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as f_json:
        f_json.write(json_str)
        f_json.flush()
        src = f_json.name
        dst = f_json.name + ".toon"

    cmd = ["npx", "--yes", "@toon-format/cli", src, "-o", dst]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"TOON CLI failed:\n{result.stderr}")

    toon_text = open(dst).read()

    j_tokens = count_tokens(json_str)
    t_tokens = count_tokens(toon_text)

    if j_tokens > 0 and t_tokens > 0:
        percent = 100 * (1 - (t_tokens / j_tokens))
        stats = (
            "=== TOKEN SAVINGS ===\n"
            f"JSON tokens: {j_tokens}\n"
            f"TOON tokens: {t_tokens}\n"
            f"Saved: {percent:.1f}%\n"
        )
    else:
        stats = "=== TOKEN SAVINGS ===\n(unavailable)\n"

    return toon_text, stats

# =====================================================================
# SANITIZER
# =====================================================================
def _looks_like_big_hex(val: Any, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    hexstr = val.replace(":", "").replace(" ", "").lower()
    return len(hexstr) >= min_len and all(c in "0123456789abcdef" for c in hexstr)

def _sanitize_layers(obj: Any, drop_keys: set[str], aggressive: bool, cutoff: int):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            if k in drop_keys or any(k.endswith(f".{s}") for s in drop_keys):
                obj.pop(k, None)
                continue
            v = obj.get(k)
            if isinstance(v, (dict, list)):
                _sanitize_layers(v, drop_keys, aggressive, cutoff)
            elif aggressive and _looks_like_big_hex(v, cutoff):
                obj.pop(k, None)
    elif isinstance(obj, list):
        for item in obj:
            _sanitize_layers(item, drop_keys, aggressive, cutoff)

# =====================================================================
# 1️⃣ PCAP → JSON
# =====================================================================
@mcp.tool
async def convert_to_json(filename: str = "", data_b64: str = "") -> str:
    if not filename and not data_b64:
        raise ValueError("Must supply filename or base64 data.")

    workdir = tempfile.mkdtemp(prefix="pcap_")
    pcap_path = os.path.join(workdir, os.path.basename(filename or "capture.pcap"))
    out_json = pcap_path + ".json"

    if data_b64:
        open(pcap_path, "wb").write(base64.b64decode(data_b64))
    else:
        shutil.copy(filename, pcap_path)

    proc = await asyncio.create_subprocess_exec(
        "tshark", "-nlr", pcap_path, "-T", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        raise RuntimeError(stderr.decode())

    open(out_json, "w").write(stdout.decode())
    return out_json

# =====================================================================
# 2️⃣ SANITIZE JSON
# =====================================================================
@mcp.tool
async def sanitize_json(json_path: str,
                        extra_drop_keys: list[str] | None = None,
                        aggressive: bool = False,
                        hex_len_cutoff: int = 256) -> str:

    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)

    raw = json.loads(open(json_path).read())
    drops = set(DEFAULT_DROP_KEYS)
    if extra_drop_keys:
        drops.update(extra_drop_keys)

    for pkt in raw:
        layers = pkt.get("_source", {}).get("layers", {})
        _sanitize_layers(layers, drops, aggressive, hex_len_cutoff)

    new_path = json_path.replace(".json", ".sanitized.json")
    open(new_path, "w").write(json.dumps(raw, indent=2))
    return new_path

# =====================================================================
# 3️⃣ JSON → TOON
# =====================================================================
@mcp.tool
async def convert_json_to_toon(json_path: str) -> dict:

    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)

    raw = json.loads(open(json_path).read())
    toon_text, stats = toon_with_stats(raw)

    toon_path = json_path.replace(".json", ".toon.txt")
    open(toon_path, "w").write(toon_text)

    return {"toon_path": toon_path, "stats": stats}

# =====================================================================
# 4️⃣ ANALYZE (NO FILESEARCH — DIRECT CONTEXT)
# =====================================================================
@mcp.tool
async def analyze_toon(toon_path: str, question: str) -> dict:
    if not os.path.exists(toon_path):
        raise FileNotFoundError(toon_path)

    toon_text = open(toon_path).read()

    # Direct inline context
    prompt = [
        question,
        "\n=== PCAP (TOON FORMAT) ===\n",
        toon_text
    ]

    resp = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
        )
    )

    return {
        "answer": resp.text,
        "toon_used": toon_path
    }

# =====================================================================
# RUN SERVER
# =====================================================================
if __name__ == "__main__":
    mcp.run()
