name = "/packetcopilot:analyze"
description = "End-to-end analysis of a PCAP file using Gemini File Search (RAG). Converts PCAP → JSON → Indexed knowledge → Answer."
args = ["question", "path?=./capture.pcap"]
prompt = """
# 1️⃣ Generate a session ID
SESSION=$(uuidgen)
echo "🆕  Session: $SESSION"

# 2️⃣ Convert PCAP file to Base64
echo "📤  Encoding $path to Base64 …"
BASE64=$(base64 -w 0 "$path")

# 3️⃣ Convert Base64 → JSON using Packet Buddy MCP
echo "🔄  Converting to JSON with tshark …"
mcp tools call convert_to_json --arguments "{
  \\"session_id\\": \\"$SESSION\\",
  \\"filename\\": \\"$(basename "$path")\\",
  \\"data_b64\\": \\"$BASE64\\"
}"

# 4️⃣ Upload + index JSON in Gemini File Search
echo "📚  Uploading and indexing JSON in Gemini File Search …"
mcp tools call upload_and_index --arguments "{
  \\"session_id\\": \\"$SESSION\\"
}"

# 5️⃣ Ask Gemini a question grounded in the indexed capture
echo "🤖  Analyzing with Gemini File Search (RAG) …"
mcp tools call analyze_pcap --arguments "{
  \\"session_id\\": \\"$SESSION\\",
  \\"question\\": \\"$question\\"
}"

# 6️⃣ Clean up temporary files
echo "🧹  Cleaning up session data …"
mcp tools call cleanup --arguments "{
  \\"session_id\\": \\"$SESSION\\"
}"
"""
