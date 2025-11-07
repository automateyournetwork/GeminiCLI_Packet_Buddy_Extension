🧠 Packet Copilot (File Search MCP Edition)

An AI-powered packet-analysis agent built with FastMCP, tshark, and Gemini File Search.
Upload a .pcap or .pcapng, convert it to JSON locally, index it in Gemini File Search, and ask Gemini 2.5 Flash grounded questions about the traffic — no local embeddings or databases required.

⚙️ Slash Commands
/packetcopilot:analyze

Description:
Upload, convert, index, and analyze a PCAP file using Gemini File Search in one automated flow.

Args:

question (string) – Your analysis prompt (e.g. "Summarize Layer 2–4 traffic")

path (optional, default ./capture.pcap) – Path to your local capture file

Flow executed behind the scenes:

Generate a new UUID session ID

Base64-encode the capture

Call convert_to_json to run tshark -T json locally

Upload the JSON to Gemini File Search via upload_and_index

Run analyze_pcap to ask your question grounded on the indexed JSON

Example:

/packetcopilot:analyze "Give me a Layer 2–4 summary of capture.pcap"

🧩 MCP Tools Exposed
Tool	Purpose	Example
convert_to_json	Runs tshark -T json on a local or base64 upload	mcp tools call convert_to_json --arguments '{"session_id":"abc","filename":"capture.pcap"}'
upload_and_index	Uploads the generated JSON to Gemini File Search for grounding	mcp tools call upload_and_index --arguments '{"session_id":"abc"}'
analyze_pcap	Asks Gemini 2.5 Flash a question grounded on the JSON store	mcp tools call analyze_pcap --arguments '{"session_id":"abc","question":"Summarize TCP activity"}'
cleanup	Deletes temporary session files and directories	mcp tools call cleanup --arguments '{"session_id":"abc"}'
🧭 Typical Workflow
/packetcopilot:analyze "Which protocols dominate this capture?"


or manually:

SESSION=$(uuidgen)
mcp tools call convert_to_json   --arguments "{\"session_id\":\"$SESSION\",\"filename\":\"capture.pcap\"}"
mcp tools call upload_and_index  --arguments "{\"session_id\":\"$SESSION\"}"
mcp tools call analyze_pcap      --arguments "{\"session_id\":\"$SESSION\",\"question\":\"Summarize Layer 2–4 flows\"}"
mcp tools call cleanup           --arguments "{\"session_id\":\"$SESSION\"}"

🧠 What Packet Copilot Does
Stage	Description
Convert	Parses PCAP locally via tshark -T json for structured packet data
Upload	Pushes the JSON to Gemini File Search for cloud indexing and grounding
Analyze	Sends your question to Gemini 2.5 Flash with File Search context
Cleanup	Removes temporary local directories and files on completion
📡 Example Prompts

“Summarize the Layer 2–4 traffic patterns.”

“Which hosts exchanged the most data?”

“List DNS queries and responses observed.”

“Any TCP retransmissions or resets?”

“Explain the main protocols and ports in this capture.”

☁️ Architecture Highlights

✅ tshark used for local parsing (no external binaries required)

✅ Gemini File Search handles embedding + retrieval (cloud RAG)

✅ No local Chroma DB or LangChain dependencies

✅ Sessions are ephemeral and isolated in temporary directories

✅ Gemini 2.5 Flash provides grounded, cited answers

🔒 Safety & Privacy

PCAP processing is local via tshark.

Only structured JSON metadata is uploaded for analysis.

Temporary session directories are cleaned after each run.

No raw payloads or PII are retained.

🧩 Use Cases

Rapid AI summaries of packet captures

Network troubleshooting (ports, flows, drops)

Security and protocol inspection tasks

Educational walkthroughs of real traffic examples