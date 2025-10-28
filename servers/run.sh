#!/usr/bin/env bash
set -euo pipefail

EXT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"
SERVERS_DIR="$EXT_DIR/servers"
VENV="$SERVERS_DIR/packetmcp"
PYTHON_BIN="${PYTHON_BIN:-python3.11}"

# --- NEW: ensure tshark is installed ---
if ! command -v tshark >/dev/null 2>&1; then
  echo "[packet] tshark not found. Installing..." >&2
  sudo apt update -y >&2
  sudo apt install -y tshark >&2
else
  echo "[packet] tshark found: $(tshark -v | head -n1)" >&2
fi

# 1) Create venv if missing
if [ ! -x "$VENV/bin/python3" ]; then
  echo "[packet] creating venv at $VENV" >&2
  "$PYTHON_BIN" -m venv "$VENV" 1>&2
  "$VENV/bin/pip" install -U pip wheel setuptools --disable-pip-version-check -q 1>&2
fi

# 2) Ensure deps (idempotent). All output -> STDERR.
if [ -f "$SERVERS_DIR/requirements.txt" ]; then
  "$VENV/bin/pip" install -r "$SERVERS_DIR/requirements.txt" \
    --disable-pip-version-check --no-input -q 1>&2
fi

# 3) Exec the MCP server (this must be the ONLY thing that writes to STDOUT)
exec "$VENV/bin/python3" "$SERVERS_DIR/server.py"
