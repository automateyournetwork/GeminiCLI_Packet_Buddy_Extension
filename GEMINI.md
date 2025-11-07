name = "/packetcopilot:analyze"
description = "End-to-end deterministic PCAP analysis using Gemini File Search."
args = ["question", "path?=./capture.pcap"]
prompt = """

1 - Generate a UUID for a session 
2 - Convert the PCAP to base64
3 - Convert the base64 to JSON using Packet Buddy API
4 - Upload the JSON to Gemini File Search
5 - Use Gemini File Search to answer the question based on the uploaded JSON

"""
