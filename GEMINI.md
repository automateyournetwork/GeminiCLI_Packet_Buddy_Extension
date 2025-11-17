1 - Start a new session and get the session ID and use that session ID throughout
2 - Convert the PCAP JSON using Packet Buddy API
4 - Santize the JSON to remove the drop fields
5 - Convert sanatized JSON to TOON
6 - Use TOON and NOT JSON (send TOON to LLM not JSON)
7 - Answer the users original prompt