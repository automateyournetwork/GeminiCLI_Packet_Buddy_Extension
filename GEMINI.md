name = "/packetcopilot:analyze"
description = "End-to-end deterministic PCAP analysis using Gemini File Search."
args = ["question", "path?=./capture.pcap"]
prompt = """

1 - Convert the PCAP JSON using Packet Buddy API
2 - Upload the JSON to Gemini File Search
3 - Santize the JSON to remove the drop fields
4 - Use Gemini File Search to answer the question based on the uploaded JSON

"""
