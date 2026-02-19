# *ARP Spoofing Detector*

A real-time **ARP spoofing detection tool** built using **Python** and **Scapy**, designed to monitor local network traffic and identify suspicious **IP ↔ MAC address changes** that indicate **ARP poisoning / Man-in-the-Middle (MITM) attacks**.


---

## *What is ARP Spoofing?*

**ARP (Address Resolution Protocol)** is used to map IP addresses to MAC addresses within a local network.

In an **ARP spoofing attack**, an attacker sends forged ARP packets to:
- Associate their MAC address with another device’s IP (often the gateway)
- Intercept or manipulate network traffic
- Perform MITM attacks, session hijacking, or credential theft

This tool detects such behavior by **observing ARP packets in real time**.

---

## *Features*

- Real-time packet sniffing
- ARP packet filtering
- Extraction of ARP fields (IP & MAC)
- Timestamped, human-readable logs
- Lightweight and memory-safe (`store=False`)
- Foundation for ARP spoof detection logic

---

## *How It Works*

1. Listens on a specified network interface
2. Captures packets using raw sockets
3. Filters only ARP packets
4. Extracts:
   - Source IP
   - Source MAC
   - Target IP
   - Target MAC
5. Prints structured logs for analysis


---

# EXECUTION FLOW 

- Program starts.
- main() creates objects.
- Sniffer begins listening.
- Packet arrives.
- packet_handler triggered.
- Extract IP and MAC.
- engine.process_reply() called.
- State updated.
- Detection rules evaluated.
- Alerts printed/logged.
