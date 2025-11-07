name = "/packetcopilot:analyze"
description = "Upload, convert, index, and analyze a PCAP using Gemini File Search."
args = ["question", "path?=./capture.pcap"]
prompt = """
SESSION=$(uuidgen)
echo "🆕  Session: $SESSION"

echo "📤  Uploading $path …"
BASE64=$(base64 -w 0 "$path")
mcp tools call convert_to_json --arguments "{\\"session_id\\": \\"$SESSION\\", \\"filename\\": \\"$(basename "$path")\\", \\"data_b64\\": \\"$BASE64\\"}"

echo "📚  Indexing capture …"
mcp tools call upload_and_index --arguments "{\\"session_id\\": \\"$SESSION\\"}"

echo "🤖  Asking Gemini File Search …"
mcp tools call analyze_pcap --arguments "{\\"session_id\\": \\"$SESSION\\", \\"question\\": \\"$question\\"}"
"""
