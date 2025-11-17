#!/usr/bin/env python3
import os, json, base64, shutil, tempfile, subprocess, asyncio
from typing import Any
from fastmcp import FastMCP
from dotenv import load_dotenv
from google import genai

# ============================================================
# INIT
# ============================================================
load_dotenv()
client = genai.Client()
mcp = FastMCP("PacketBuddy")   # MUST MATCH EXTENSION DIR NAME

DEFAULT_DROP_KEYS = {
    "data.data",
    "tcp.payload",
    "tls.app_data",
    "http.file_data",
    "usb.capdata",
    "data.text",
}

# ============================================================
# TOKENIZER
# ============================================================
try:
    import tiktoken
    tokenizer = tiktoken.get_encoding("o200k_base")
except:
    tokenizer = None

def count_tokens(txt: str) -> int:
    if not tokenizer:
        return -1
    try:
        return len(tokenizer.encode(txt))
    except:
        return -1

# ============================================================
# SAFE JSON NORMALIZATION
# ============================================================
def make_json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    return obj

# ============================================================
# TOON CONVERSION
# ============================================================
def toon_with_stats(json_obj: Any) -> tuple[str, str]:
    safe = make_json_safe(json_obj)
    json_str = json.dumps(safe, indent=2)

    # temp file
    with tempfile.NamedTemporaryFile(mode="w+", suffix=".json", delete=False) as jf:
        jf.write(json_str)
        jf.flush()
        src = jf.name
        dst = jf.name + ".toon"

    cmd = ["npx", "--yes", "@toon-format/cli", src, "-o", dst]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"TOON CLI failed:\n{result.stderr}")

    if not os.path.exists(dst):
        raise RuntimeError("TOON CLI produced no output file")

    toon_text = open(dst).read()

    j_tokens = count_tokens(json_str)
    t_tokens = count_tokens(toon_text)

    if j_tokens > 0 and t_tokens > 0:
        saved = 100 * (1 - t_tokens / j_tokens)
        stats = (
            "=== TOKEN SAVINGS ===\n"
            f"JSON tokens: {j_tokens}\n"
            f"TOON tokens: {t_tokens}\n"
            f"Saved: {saved:.1f}%\n"
        )
    else:
        stats = "=== TOKEN SAVINGS ===\n(unavailable)\n"

    return toon_text, stats

# ============================================================
# SANITIZE HELPERS
# ============================================================
def _looks_like_big_hex(val: Any, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    v = val.replace(":", "").replace(" ", "").lower()
    return len(v) >= min_len and all(c in "0123456789abcdef" for c in v)

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

# ============================================================
# 1️⃣ PacketBuddy: PCAP → JSON
# ============================================================
@mcp.tool
async def pb_convert_to_json(filename: str = "", data_b64: str = "") -> str:
    if not filename and not data_b64:
        raise ValueError("Must supply filename or base64 data")

    work = tempfile.mkdtemp(prefix="pb_")
    pcap = os.path.join(work, os.path.basename(filename or "capture.pcap"))
    out_json = pcap + ".json"

    if data_b64:
        open(pcap, "wb").write(base64.b64decode(data_b64))
    else:
        shutil.copy(filename, pcap)

    proc = await asyncio.create_subprocess_exec(
        "tshark", "-nlr", pcap, "-T", "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    # fallback for pcapng
    if proc.returncode != 0 and b"pcapng" in stderr.lower():
        fixed = pcap + ".fixed"
        await asyncio.create_subprocess_exec("editcap", "-F", "libpcap", pcap, fixed)
        proc2 = await asyncio.create_subprocess_exec(
            "tshark", "-nlr", fixed, "-T", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc2.communicate()
        if proc2.returncode != 0:
            raise RuntimeError(stderr.decode())
    elif proc.returncode != 0:
        raise RuntimeError(stderr.decode())

    open(out_json, "w").write(stdout.decode())
    return out_json

# ============================================================
# 2️⃣ PacketBuddy: SANITIZE JSON
# ============================================================
@mcp.tool
async def pb_sanitize_json(json_path: str,
                           extra_drop_keys=None,
                           aggressive: bool = False,
                           hex_len_cutoff: int = 256) -> str:

    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)

    raw = json.load(open(json_path))
    drops = set(DEFAULT_DROP_KEYS)
    if extra_drop_keys:
        drops.update(extra_drop_keys)

    for pkt in raw:
        layers = pkt.get("_source", {}).get("layers", {})
        _sanitize_layers(layers, drops, aggressive, hex_len_cutoff)

    # time-stamped file name so Gemini never reuses stale ones
    ts = int(asyncio.get_event_loop().time())
    out = json_path.replace(".json", f".sanitized.{ts}.json")

    open(out, "w").write(json.dumps(raw, indent=2))
    return out

# ============================================================
# 3️⃣ PacketBuddy: JSON → TOON
# ============================================================
@mcp.tool
async def pb_convert_json_to_toon(json_path: str) -> dict:
    if not os.path.exists(json_path):
        raise FileNotFoundError(json_path)

    raw = json.load(open(json_path))
    toon_text, stats = toon_with_stats(raw)

    toon_path = json_path.replace(".json", ".toon.txt")
    open(toon_path, "w").write(toon_text)

    return {"toon_path": toon_path, "stats": stats}

# ============================================================
# 4️⃣ PacketBuddy: ANALYZE TOON
# ============================================================
@mcp.tool
async def pb_analyze_toon(toon_path: str, question: str) -> dict:
    if not os.path.exists(toon_path):
        raise FileNotFoundError(toon_path)

    toon_text = open(toon_path).read()

    contents = [
        f"User question:\n{question}",
        "=== PCAP (TOON FORMAT) ===",
        toon_text,
    ]

    resp = await asyncio.get_event_loop().run_in_executor(
        None,
        lambda: client.models.generate_content(
            model="gemini-2.5-flash",
            contents=contents,
        ),
    )

    return {
        "answer": resp.text,
        "debug": f"TOON chars: {len(toon_text)}",
    }

# ============================================================
# RUN MCP SERVER
# ============================================================
if __name__ == "__main__":
    mcp.run()
