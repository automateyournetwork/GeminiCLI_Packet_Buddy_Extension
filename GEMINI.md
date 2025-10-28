🦈 Packet Buddy Extension (PCAP → JSON → AI Analysis)

This extension connects Gemini-CLI to the Packet Copilot MCP Server, giving you a full AI-driven packet-analysis workflow.
It lets you upload, convert, sanitize, index, and query packet captures directly from Gemini-CLI using simple /pcap: commands.

⚙️ Commands

/pcap — quick help and examples.

/pcap:new — start a new Packet Buddy analysis session.
Returns a unique session_id that subsequent commands reuse.

/pcap:upload — upload a .pcap or .pcapng file (base64-encoded behind the scenes).
Args:
• path (local path to capture)
• session_id (optional; auto-creates if omitted)

/pcap:convert — run tshark -T json on the uploaded file.
Args: session_id

/pcap:sanitize — strip heavy payloads, hex blobs, and PII.
Args: session_id, aggressive (bool, default false)

/pcap:index — build embeddings & Chroma vector DB for RAG.
Args: session_id

/pcap:describe — return quick stats (total packets, top ports, talkers).
Args: session_id

/pcap:analyze — ask GPT-4o any question about the capture.
Args: session_id, question (string)

/pcap:cleanup — delete temporary artifacts for that session.
Args: session_id

🧭 Typical Flow
/pcap:new
/pcap:upload path=./captures/capture.pcap
/pcap:convert
/pcap:sanitize aggressive=true
/pcap:index
/pcap:describe
/pcap:analyze "Summarize major protocols and top talkers"
/pcap:cleanup

This flow is automated by Gemini-CLI you use need to provide the prompt and path the pcap. 

🧠 What Packet Buddy Does

Converts PCAP → structured JSON via tshark

Sanitizes payloads to protect sensitive data

Generates semantic chunks → embeddings → Chroma DB

Uses GPT-4o for deep packet analysis & troubleshooting

Returns answers in Markdown with emoji and protocol context

📡 Example Prompts

“Which hosts exchanged the most traffic?”

“Do you see any packet loss or retransmissions?”

“List the DNS queries observed in this capture.”

“Summarize HTTP requests and responses.”

“Show BGP session establishments and state changes.”

🔒 Safety

Payload scrubbing removes hex blobs

Keeps each session isolated in a temporary directory

You own your data — no uploads outside your machine

🧩 Use Cases

Quick protocol summaries for Wireshark captures

AI-assisted troubleshooting of latency, drops, or flows

Education / training — “Explain this packet like I’m a student”