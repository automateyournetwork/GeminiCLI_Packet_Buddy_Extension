name = "/packetcopilot:analyze"
description = "End-to-end deterministic PCAP analysis using Gemini File Search."
args = ["question", "path?=./capture.pcap"]
prompt = """

1 - Convert the PCAP JSON using Packet Buddy API
3 - Santize the JSON to remove the drop fields
3 - Convert sanatized JSON to TOON
4 - Use TOON and NOT JSON (send TOON to LLM not JSON)
5 - Answer the users original prompt

"""
