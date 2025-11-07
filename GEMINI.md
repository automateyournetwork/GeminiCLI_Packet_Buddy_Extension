name = "/packetcopilot:analyze"
description = "End-to-end deterministic PCAP analysis using Gemini File Search."
args = ["question", "path?=./capture.pcap"]
prompt = """
set -euo pipefail

SESSION=$(uuidgen)
echo "🆕  Session: $SESSION"

echo "📤  Encoding $path to Base64 …"
BASE64=$(base64 -w 0 "$path")

echo "🔄  Converting PCAP → JSON …"
mcp tools call convert_to_json --arguments "{
  \\"session_id\\": \\"$SESSION\\",
  \\"filename\\": \\"$(basename "$path")\\",
  \\"data_b64\\": \\"$BASE64\\"
}" || { echo "❌ convert_to_json failed"; exit 1; }

echo "📚  Uploading + indexing JSON in Gemini File Search …"
mcp tools call upload_and_index --arguments "{
  \\"session_id\\": \\"$SESSION\\"
}" || { echo "❌ upload_and_index failed"; exit 1; }

echo "🤖  Asking Gemini File Search …"
mcp tools call analyze_pcap --arguments "{
  \\"session_id\\": \\"$SESSION\\",
  \\"question\\": \\"$question\\"
}" || { echo "❌ analyze_pcap failed"; exit 1; }

echo "🧹  Cleaning up temporary session files …"
mcp tools call cleanup --arguments "{
  \\"session_id\\": \\"$SESSION\\"
}" || echo "⚠️  Cleanup skipped (non-fatal)"
"""
