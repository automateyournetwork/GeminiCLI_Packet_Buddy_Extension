# mcp_server.py
import os, base64, json, uuid, subprocess, tempfile, shutil
from collections import defaultdict
from fastmcp import FastMCP

# === LangChain / RAG bits (mirrors your Streamlit flow, no st.*) ===
import ipaddress, re
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_classic.memory import ConversationBufferMemory
from langchain_classic.chains import ConversationalRetrievalChain
from langchain_community.document_loaders import JSONLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter as SemanticChunker
from langchain_community.vectorstores import Chroma
from langchain_core.prompts import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
    MessagesPlaceholder
)

# --- Sanitization helpers ---
import time
from typing import Any

# Fields that are noisy, large, or risky (you can extend this anytime)
DEFAULT_DROP_KEYS = {
    # generic raw/hex
    "data", "data.data", "frame.raw",
    # TCP/UDP reassembly + payloads
    "tcp.payload", "tcp.segment_data", "tcp.reassembled.data",
    "udp.payload",
    # TLS bulk
    "tls.segment.data", "tls.handshake.random_bytes",
    "tls.handshake.certificate", "ssl.handshake.certificate",
    # QUIC bulk
    "quic.payload", "quic.payload_raw",
    # HTTP secrets/bodies
    "http.file_data", "http.authorization", "http.cookie", "http.cookie_pair",
    # SMB/NFS/file blobs
    "smb.data", "smb2.data", "nfs.fattr",
    # Auth/Directory values that often include PII/creds
    "kerberos.CNameString", "ntlmssp.auth", "radius.Attribute.Value",
    "ldap.attributeValue",
    # Big X.509 extension dumps
    "x509ce.extension",
}

PACKET_WHISPERER = """
        You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability.

        🌍 **Geolocation Handling**
        - If a public IP appears in the data, AI lookup results will be included **before** you answer.
        - Do **NOT** estimate IP locations yourself—use the provided geolocation data.        

        **Protocol Hints:**
        - 🌐 **HTTP**: `tcp.port == 80`
        - 🔐 **HTTPS**: `tcp.port == 443`
        - 🛠 **SNMP**: `udp.port == 161` or `udp.port == 162`
        - ⏲ **NTP**: `udp.port == 123`
        - 📁 **FTP**: `tcp.port == 21`
        - 🔒 **SSH**: `tcp.port == 22`
        - 🔄 **BGP**: `tcp.port == 179`
        - 🌐 **OSPF**: IP protocol 89 (works directly on IP, no TCP/UDP)
        - 🔍 **DNS**: `udp.port == 53` (or `tcp.port == 53` for larger queries/zone transfers)
        - 💻 **DHCP**: `udp.port == 67` (server), `udp.port == 68` (client)
        - 📧 **SMTP**: `tcp.port == 25` (email sending)
        - 📬 **POP3**: `tcp.port == 110` (email retrieval)
        - 📥 **IMAP**: `tcp.port == 143` (advanced email retrieval)
        - 🔒 **LDAPS**: `tcp.port == 636` (secure LDAP)
        - 📞 **SIP**: `tcp.port == 5060` or `udp.port == 5060` (for multimedia sessions)
        - 🎥 **RTP**: No fixed port, commonly used with SIP for multimedia streams.
        - 🖥 **Telnet**: `tcp.port == 23`
        - 📂 **TFTP**: `udp.port == 69`
        - 💾 **SMB**: `tcp.port == 445` (Server Message Block)
        - 🌍 **RDP**: `tcp.port == 3389` (Remote Desktop Protocol)
        - 📡 **SNTP**: `udp.port == 123` (Simple Network Time Protocol)
        - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
        - 🌉 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
        - 🔗 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
        - 🖧 **L2TP**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
        - 💼 **PPTP**: `tcp.port == 1723` (Point-to-Point Tunneling Protocol)
        - 🔌 **Telnet**: `tcp.port == 23` (Unencrypted remote access)
        - 🛡 **Kerberos**: `tcp.port == 88` (Authentication protocol)
        - 🖥 **VNC**: `tcp.port == 5900` (Virtual Network Computing)
        - 🌐 **LDAP**: `tcp.port == 389` (Lightweight Directory Access Protocol)
        - 📡 **NNTP**: `tcp.port == 119` (Network News Transfer Protocol)
        - 📠 **RSYNC**: `tcp.port == 873` (Remote file sync)
        - 📡 **ICMP**: IP protocol 1 (Internet Control Message Protocol, no port)
        - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation, no port)
        - 📶 **IKE**: `udp.port == 500` (Internet Key Exchange for VPNs)
        - 🔐 **ISAKMP**: `udp.port == 4500` (for VPN traversal)
        - 🛠 **Syslog**: `udp.port == 514`
        - 🖨 **IPP**: `tcp.port == 631` (Internet Printing Protocol)
        - 📡 **RADIUS**: `udp.port == 1812` (Authentication), `udp.port == 1813` (Accounting)
        - 💬 **XMPP**: `tcp.port == 5222` (Extensible Messaging and Presence Protocol)
        - 🖧 **Bittorrent**: `tcp.port == 6881-6889` (File-sharing protocol)
        - 🔑 **OpenVPN**: `udp.port == 1194`
        - 🖧 **NFS**: `tcp.port == 2049` (Network File System)
        - 🔗 **Quic**: `udp.port == 443` (UDP-based transport protocol)
        - 🌉 **STUN**: `udp.port == 3478` (Session Traversal Utilities for NAT)
        - 🛡 **ESP**: IP protocol 50 (Encapsulating Security Payload for VPNs)
        - 🛠 **LDP**: `tcp.port == 646` (Label Distribution Protocol for MPLS)
        - 🌐 **HTTP/2**: `tcp.port == 8080` (Alternate HTTP port)
        - 📁 **SCP**: `tcp.port == 22` (Secure file transfer over SSH)
        - 🔗 **GTP-C**: `udp.port == 2123` (GPRS Tunneling Protocol Control)
        - 📶 **GTP-U**: `udp.port == 2152` (GPRS Tunneling Protocol User)
        - 🔄 **BGP**: `tcp.port == 179` (Border Gateway Protocol)
        - 🌐 **OSPF**: IP protocol 89 (Open Shortest Path First)
        - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
        - 🔄 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
        - 🌉 **LDP**: `tcp.port == 646` (Label Distribution Protocol)
        - 🛰 **IS-IS**: ISO protocol 134 (Intermediate System to Intermediate System, works directly on IP)
        - 🔄 **IGMP**: IP protocol 2 (Internet Group Management Protocol, for multicast)
        - 🔄 **PIM**: IP protocol 103 (Protocol Independent Multicast)
        - 📡 **RSVP**: IP protocol 46 (Resource Reservation Protocol)
        - 🔄 **Babel**: `udp.port == 6696` (Babel routing protocol)
        - 🔄 **DVMRP**: IP protocol 2 (Distance Vector Multicast Routing Protocol)
        - 🛠 **VRRP**: `ip.protocol == 112` (Virtual Router Redundancy Protocol)
        - 📡 **HSRP**: `udp.port == 1985` (Hot Standby Router Protocol)
        - 🔄 **LISP**: `udp.port == 4341` (Locator/ID Separation Protocol)
        - 🛰 **BFD**: `udp.port == 3784` (Bidirectional Forwarding Detection)
        - 🌍 **HTTP/3**: `udp.port == 443` (Modern web traffic)
        - 🛡 **IPSec**: IP protocol 50 (ESP), IP protocol 51 (AH)
        - 📡 **L2TPv3**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
        - 🛰 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
        - 🔑 **IKEv2**: `udp.port == 500`, `udp.port == 4500` (Internet Key Exchange Version 2 for VPNs)
        - 🛠 **NetFlow**: `udp.port == 2055` (Flow monitoring)
        - 🌐 **CARP**: `ip.protocol == 112` (Common Address Redundancy Protocol)
        - 🌐 **SCTP**: `tcp.port == 9899` (Stream Control Transmission Protocol)
        - 🖥 **VNC**: `tcp.port == 5900-5901` (Virtual Network Computing)
        - 🌐 **WebSocket**: `tcp.port == 80` (ws), `tcp.port == 443` (wss)
        - 🔗 **NTPv4**: `udp.port == 123` (Network Time Protocol version 4)
        - 📞 **MGCP**: `udp.port == 2427` (Media Gateway Control Protocol)
        - 🔐 **FTPS**: `tcp.port == 990` (File Transfer Protocol Secure)
        - 📡 **SNMPv3**: `udp.port == 162` (Simple Network Management Protocol version 3)
        - 🔄 **VXLAN**: `udp.port == 4789` (Virtual Extensible LAN)
        - 📞 **H.323**: `tcp.port == 1720` (Multimedia communications protocol)
        - 🔄 **Zebra**: `tcp.port == 2601` (Zebra routing daemon control)
        - 🔄 **LACP**: `udp.port == 646` (Link Aggregation Control Protocol)
        - 📡 **SFlow**: `udp.port == 6343` (SFlow traffic monitoring)
        - 🔒 **OCSP**: `tcp.port == 80` (Online Certificate Status Protocol)
        - 🌐 **RTSP**: `tcp.port == 554` (Real-Time Streaming Protocol)
        - 🔄 **RIPv2**: `udp.port == 521` (Routing Information Protocol version 2)
        - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation)
        - 🌐 **L2F**: `tcp.port == 1701` (Layer 2 Forwarding Protocol)
        - 🌐 **RSTP**: No port (Rapid Spanning Tree Protocol, L2 protocol)
        - 📞 **RTCP**: Dynamic ports (Real-time Transport Control Protocol)

        **Additional Info:**
        - Include context about traffic patterns (e.g., latency, packet loss).
        - Use protocol hints when analyzing traffic to provide clear explanations of findings.
        - Highlight significant events or anomalies in the packet capture based on the protocols.
        - Identify source and destination IP addresses
        - Identify source and destination MAC addresses
        - Perform MAC OUI lookup and provide the manufacturer of the NIC 
        - Look for dropped packets; loss; jitter; congestion; errors; or faults and surface these issues to the user

        Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
"""
load_dotenv()
assert os.getenv("OPENAI_API_KEY"), "OPENAI_API_KEY is required for Gemini."

mcp = FastMCP("PacketCopilot")

# session_id -> state
SESSIONS = defaultdict(dict)  # keys: dir, pcap_path, json_path, docs, pages, qa

# ---------- helpers ----------
def _session(session_id: str) -> dict:
    s = SESSIONS[session_id]
    if "dir" not in s:
        s["dir"] = tempfile.mkdtemp(prefix=f"pcap_{session_id}_")
    return s

def _pcap_to_json(pcap_path: str, json_path: str):
    cmd = f'tshark -nlr "{pcap_path}" -T json > "{json_path}"'
    subprocess.run(cmd, shell=True, check=True)
    # scrub hex payloads similar to your app
    with open(json_path, "r") as f:
        data = json.load(f)
    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})
        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        if isinstance(tcp, dict):
            tcp.pop("tcp.payload", None)
            tcp.pop("tcp.segment_data", None)
            tcp.pop("tcp.reassembled.data", None)
        if isinstance(udp, dict):
            udp.pop("udp.payload", None)
        tls = layers.get("tls", {})
        if isinstance(tls, dict):
            tls.pop("tls.segment.data", None)
    with open(json_path, "w") as f:
        json.dump(data, f, indent=2)

def _build_docs_from_json(json_path: str):
    loader = JSONLoader(
        file_path=json_path,
        jq_schema=".[] | ._source.layers | del(.data)",
        text_content=False
    )
    pages = loader.load_and_split()
    splitter = SemanticChunker(chunk_size=1500, chunk_overlap=100)  # ✅ no embeddings here
    docs = splitter.split_documents(pages)
    return docs, pages

def _return_system_text(pcap_pages) -> str:
    pcap_summary = " ".join([str(p) for p in pcap_pages[:5]])
    pcap_summary = pcap_summary.replace("{", "{{").replace("}", "}}")
    return f"""
You are an expert assistant specialized in analyzing PCAPs. Use only the provided packet_capture_info.
Be concise, structured, and add brief protocol hints when relevant.

packet_capture_info (sample):
{pcap_summary}
"""

def _build_chain(docs, priming_text, persist_dir: str):
    embeddings = HuggingFaceEmbeddings(model_name='all-MiniLM-L6-v2', model_kwargs={"device": "cpu"})
    vectordb = Chroma.from_documents(docs, embeddings, persist_directory=persist_dir)
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-pro-preview-03-25", temperature=0.6)
    prompt = ChatPromptTemplate.from_messages([
        SystemMessagePromptTemplate.from_template(priming_text + "\n\n{context}"),
        MessagesPlaceholder(variable_name="chat_history"),
        HumanMessagePromptTemplate.from_template("{question}")
    ])
    memory = ConversationBufferMemory(memory_key="chat_history", return_messages=True)
    qa = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vectordb.as_retriever(search_kwargs={"k": 50}),
        memory=memory,
        combine_docs_chain_kwargs={'prompt': prompt},
        get_chat_history=lambda x: x,
    )
    return qa

def _looks_like_big_hex(val: Any, min_len: int) -> bool:
    if not isinstance(val, str):
        return False
    v = val.replace(":", "").replace(" ", "").lower()
    return len(v) >= min_len and all(c in "0123456789abcdef" for c in v)

def _sanitize_layers(obj: Any, drop_keys: set[str], aggressive: bool, hex_len_cutoff: int):
    if isinstance(obj, dict):
        for k in list(obj.keys()):
            # Drop by exact key OR dotted suffix (e.g., match tls.segment.data)
            if k in drop_keys or any(k.endswith(f".{suf}") for suf in drop_keys):
                obj.pop(k, None)
                continue
            v = obj.get(k)
            if isinstance(v, (dict, list)):
                _sanitize_layers(v, drop_keys, aggressive, hex_len_cutoff)
            else:
                if aggressive and _looks_like_big_hex(v, hex_len_cutoff):
                    obj.pop(k, None)
    elif isinstance(obj, list):
        for item in obj:
            _sanitize_layers(item, drop_keys, aggressive, hex_len_cutoff)

def _escape_braces(text: str) -> str:
    return text.replace("{", "{{").replace("}", "}}")

def _fast_stats(json_path: str, top_n: int = 5):
    """Cheap grounding: total packets, duration, top dst ports, top talkers."""
    if not (json_path and os.path.exists(json_path)):
        return {}
    with open(json_path, "r") as f:
        data = json.load(f)

    total = len(data)
    by_l4, talkers = {}, {}
    first_ts = last_ts = None

    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})

        frame = layers.get("frame", {})
        ts = frame.get("frame.time_epoch") or frame.get("frame.time_relative")
        try:
            if ts is not None:
                tsf = float(ts)
                first_ts = tsf if first_ts is None or tsf < first_ts else first_ts
                last_ts  = tsf if last_ts  is None or tsf > last_ts  else last_ts
        except Exception:
            pass

        tcp, udp = layers.get("tcp", {}), layers.get("udp", {})
        if isinstance(tcp, dict) and tcp.get("tcp.dstport"):
            key = f"tcp/{tcp['tcp.dstport']}"
            by_l4[key] = by_l4.get(key, 0) + 1
        if isinstance(udp, dict) and udp.get("udp.dstport"):
            key = f"udp/{udp['udp.dstport']}"
            by_l4[key] = by_l4.get(key, 0) + 1

        ip = layers.get("ip", {})
        if isinstance(ip, dict) and ip.get("ip.src") and ip.get("ip.dst"):
            k = f"{ip['ip.src']}→{ip['ip.dst']}"
            talkers[k] = talkers.get(k, 0) + 1

    top_ports = sorted(by_l4.items(), key=lambda x: -x[1])[:top_n]
    top_pairs = sorted(talkers.items(), key=lambda x: -x[1])[:top_n]
    duration = None
    if first_ts is not None and last_ts is not None:
        try:
            duration = max(0.0, last_ts - first_ts)
        except Exception:
            pass

    return {
        "total_packets": total,
        "duration_seconds": duration,
        "top_ports": top_ports,
        "top_talkers": top_pairs,
    }

def _guided_question(s: dict, user_q: str) -> str:
    """Combine PACKET_WHISPERER + fast stats + small sample to steer the LLM."""
    stats = _fast_stats(s.get("json_path"))
    pages = s.get("pages", [])
    sample = " ".join([str(p) for p in pages[:5]])

    sample = _escape_braces(sample)
    user_q = _escape_braces(user_q)

    stats_md = []
    if stats:
        stats_md.append(f"- Total packets: **{stats['total_packets']}**")
        if stats.get("duration_seconds") is not None:
            stats_md.append(f"- Duration (s): **{stats['duration_seconds']:.3f}**")
        if stats.get("top_ports"):
            stats_md.append("- Top ports: " + ", ".join([f"{k} ({v})" for k, v in stats["top_ports"]]))
        if stats.get("top_talkers"):
            stats_md.append("- Top talkers: " + ", ".join([f"{k} ({v})" for k, v in stats["top_talkers"]]))
    context_block = "\n".join(stats_md) if stats_md else "No computed stats available."

    return (
        f"{PACKET_WHISPERER}\n\n"
        f"### Context snapshot\n{context_block}\n\n"
        f"### Packet sample (sanitized)\n{sample}\n\n"
        f"### User question\n{user_q}\n\n"
        f"### Instructions\n"
        f"- Use the snapshot + sample for grounding.\n"
        f"- Cite concrete src/dst IPs and L4 ports where relevant.\n"
        f"- Summarize findings and list next troubleshooting steps.\n"
    )

# ---------- MCP tools ----------
@mcp.tool
def new_session() -> str:
    """Create a new analysis session and return its session_id."""
    sid = str(uuid.uuid4())
    _session(sid)
    return sid

@mcp.tool
def upload_pcap_base64(session_id: str, filename: str, data_b64: str) -> str:
    """
    Upload a PCAP/PCAPNG (base64 string). Returns server-local pcap path.
    Note: nginx client_max_body_size may limit size (base64 adds ~33%).
    """
    s = _session(session_id)
    raw = base64.b64decode(data_b64)
    pcap_path = os.path.join(s["dir"], os.path.basename(filename))
    with open(pcap_path, "wb") as f:
        f.write(raw)
    s["pcap_path"] = pcap_path
    return pcap_path

@mcp.tool
def convert_to_json(session_id: str) -> str:
    """
    Convert the uploaded PCAP to JSON via tshark and scrub payloads.
    Returns server-local JSON path.
    """
    s = _session(session_id)
    if not s.get("pcap_path"):
        raise ValueError("No PCAP uploaded. Call upload_pcap_base64 first.")
    json_path = s["pcap_path"] + ".json"
    _pcap_to_json(s["pcap_path"], json_path)
    s["json_path"] = json_path
    return json_path

@mcp.tool
def sanitize_json(session_id: str,
                  extra_drop_keys: list[str] | None = None,
                  aggressive: bool = False,
                  hex_len_cutoff: int = 256) -> str:
    """
    Remove large/raw payload fields from the session JSON before vectorization.
    Returns path to a new sanitized JSON file and updates the session to use it.

    Args:
      session_id: active session id
      extra_drop_keys: optional list of additional keys to drop
      aggressive: also remove very large hex-like strings anywhere (heuristic)
      hex_len_cutoff: size threshold for aggressive hex stripping
    """
    s = _session(session_id)
    json_path = s.get("json_path")
    if not json_path or not os.path.exists(json_path):
        raise ValueError("No JSON found. Run convert_to_json first.")

    with open(json_path, "r") as f:
        data = json.load(f)

    drops = set(DEFAULT_DROP_KEYS)
    if extra_drop_keys:
        drops.update(extra_drop_keys)

    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})
        _sanitize_layers(layers, drops, aggressive, hex_len_cutoff)

    out_path = json_path.replace(".json", f".sanitized.{int(time.time())}.json")
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    # Point the session to the sanitized file for downstream indexing
    s["json_path"] = out_path
    return out_path

@mcp.tool
def index_pcap(session_id: str) -> str:
    """
    Build embeddings, split to semantic chunks, create Chroma + RAG chain.
    Returns a short summary of index stats.
    """
    s = _session(session_id)
    if not s.get("json_path"):
        raise ValueError("No JSON found. Call convert_to_json first.")
    docs, pages = _build_docs_from_json(s["json_path"])
    if not docs:
        raise ValueError("No documents generated from the PCAP JSON.")
    s["docs"] = docs
    s["pages"] = pages
    priming = _return_system_text(pages)
    persist_dir = os.path.join(s["dir"], f"chroma_{session_id}")
    s["qa"] = _build_chain(docs, priming, persist_dir)
    return f"Indexed {len(docs)} chunks from {len(pages)} packets."

@mcp.tool
def analyze_pcap(session_id: str, question: str) -> dict:
    """
    Ask a question against the indexed PCAP (RAG over Chroma + Gemini),
    enriched with protocol hints + quick capture stats.
    """
    s = _session(session_id)
    qa = s.get("qa")
    if qa is None:
        return {"error": "PCAP not indexed yet. Call index_pcap first."}

    final_q = _guided_question(s, question)
    print("[analyze_pcap] running QA with guided question...")
    resp = qa({"question": final_q})
    print("[analyze_pcap] response received.")
    return {
        "answer": resp.get("answer", "No response generated."),
        "meta": {
            "docs": len(s.get("docs", [])),
            "pages": len(s.get("pages", []))
        }
    }

@mcp.tool
def describe_pcap(session_id: str) -> dict:
    """
    Return quick stats from the current JSON (no LLM).
    """
    s = _session(session_id)
    stats = _fast_stats(s.get("json_path"))
    if not stats:
        return {"error": "No JSON found. Run convert_to_json (and sanitize_json) first."}
    return stats

@mcp.tool
def cleanup(session_id: str) -> str:
    """Delete session artifacts."""
    s = SESSIONS.pop(session_id, None)
    if s and (wd := s.get("dir")) and os.path.exists(wd):
        shutil.rmtree(wd, ignore_errors=True)
    return "ok"

if __name__ == "__main__":
    # http streamable endpoint at /mcp/
    mcp.run()