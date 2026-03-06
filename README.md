# ARP Spoofing Detector

A **real-time ARP spoofing detection tool** built using **Python** and **Scapy** that monitors local network traffic and detects suspicious **IP ↔ MAC address changes** which may indicate **ARP poisoning or Man-in-the-Middle (MITM) attacks**.

The tool passively observes ARP traffic and alerts when an IP address suddenly maps to a different MAC address than previously observed.

This project demonstrates practical concepts in:

- Network packet inspection
- Protocol analysis
- Intrusion detection
- Cybersecurity monitoring tools

---

# What is ARP?

**ARP (Address Resolution Protocol)** is used inside a **Local Area Network (LAN)** to map an **IP address to a MAC address**.

### Example

```
IP Address        MAC Address
192.168.1.1  ->   AA:BB:CC:DD:EE:FF
```

When a device wants to communicate with another device in the same network, it sends an **ARP request**:

> "Who has this IP address? Tell me your MAC address."

The device that owns that IP responds with an **ARP reply**, allowing devices to communicate.

---

# What is ARP Spoofing?

**ARP Spoofing (ARP Poisoning)** is an attack where a malicious device sends **forged ARP packets** to associate its **MAC address with another device's IP address**.

Most commonly, attackers impersonate the **network gateway**.

### Example Attack

```
Gateway IP        -> Attacker MAC
192.168.1.1       -> 11:22:33:44:55:66
```

This causes victims to send their traffic through the attacker.

### Possible consequences

- Man-in-the-Middle (MITM) attacks
- Credential theft
- Session hijacking
- Packet manipulation
- Traffic monitoring

Because ARP **has no authentication mechanism**, devices trust the **latest ARP response they receive**.

---

# Project Features

- Real-time network packet sniffing
- ARP packet filtering
- Extraction of ARP fields (IP & MAC)
- Detection of **IP ↔ MAC inconsistencies**
- Timestamped console alerts
- Lightweight design (`store=False`)
- Modular detection engine
- Clean logging output

---

# How the Detection Works

The tool continuously monitors ARP traffic and maintains an **internal mapping table** of:

```
IP Address -> MAC Address
```

Each time an ARP packet is captured:

1. The program extracts packet fields.
2. It checks whether the IP has already been observed.
3. If the same IP appears with a **different MAC address**, an alert is triggered.

This behavior strongly indicates a **potential ARP spoofing attempt**.

---

# Execution Flow

```
Program Start
      │
      ▼
main() initializes components
      │
      ▼
Network sniffer starts
      │
      ▼
ARP packet received
      │
      ▼
packet_handler() triggered
      │
      ▼
Extract IP and MAC fields
      │
      ▼
engine.process_reply()
      │
      ▼
State updated
      │
      ▼
Detection rules evaluated
      │
      ▼
Alert generated if suspicious activity detected
```

---

# Example Output

```
[INFO] ARP Reply Captured

Source IP   : 192.168.1.1
Source MAC  : AA:BB:CC:DD:EE:FF
Target IP   : 192.168.1.5
Target MAC  : FF:EE:DD:CC:BB:AA

--------------------------------------------------

[ALERT] Possible ARP Spoofing Detected!

IP Address: 192.168.1.1
Old MAC   : AA:BB:CC:DD:EE:FF
New MAC   : 11:22:33:44:55:66
```

---

# Requirements

- Python 3.x
- Scapy
- Linux / Kali Linux / Parrot OS recommended
- Root privileges (required for packet sniffing)

---

# Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/arp-spoof-detector.git
cd arp-spoof-detector
```

Install dependencies:

```bash
pip install scapy
```

---

# Usage

Run the detector with root privileges:

```bash
sudo python3 main.py
```

Optionally specify the interface:

```bash
sudo python3 main.py -i eth0
```

---

# Project Structure

```
arp-spoof-detector
│
├── main.py
├── sniffer.py
├── detection_engine.py
├── utils.py
└── README.md
```

---

# Educational Purpose

This project was built to demonstrate:

- Low-level packet sniffing
- Network protocol inspection
- Intrusion detection fundamentals
- Cybersecurity monitoring techniques

It can serve as a **foundation for building more advanced LAN intrusion detection systems**.

---

# Future Improvements

Possible enhancements include:

- Persistent ARP table tracking
- Logging alerts to files
- Email / Telegram alert notifications
- GUI dashboard
- Machine learning anomaly detection
- Integration with IDS systems

---

# Disclaimer

This tool is intended **for educational and defensive security purposes only**.

Do **not use it on networks without permission**.

---

# License

MIT License
