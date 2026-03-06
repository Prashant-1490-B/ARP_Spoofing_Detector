# ARP Spoofing Detector

![Python](https://img.shields.io/badge/Python-v3.2-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Security](https://img.shields.io/badge/Domain-Network%20Security-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

A **real-time ARP spoofing detection tool** built using **Python and Scapy** that monitors local network traffic and detects suspicious **IP ↔ MAC address changes** which may indicate **ARP poisoning or Man-in-the-Middle (MITM) attacks**.

This project demonstrates **low-level packet inspection, network monitoring, and intrusion detection concepts** used in cybersecurity.

---

# Table of Contents

- Overview
- What is ARP
- What is ARP Spoofing
- Features
- Architecture
- Detection Logic
- Execution Flow
- Installation
- Usage
- Example Output
- Project Structure
- Future Improvements
- Disclaimer
- License

---

# Overview

ARP spoofing attacks manipulate the **ARP table of devices in a LAN** by sending forged ARP packets.

This tool passively monitors network traffic and detects when:

```
An IP address suddenly maps to a different MAC address
```

Such behavior is a strong indicator of **ARP poisoning or MITM activity**.

---

# What is ARP?

**ARP (Address Resolution Protocol)** maps an **IP address** to a **MAC address** within a local network.

Example:

```
192.168.1.1  →  AA:BB:CC:DD:EE:FF
```

When a device wants to communicate with another device in the same LAN, it sends an **ARP request**:

> "Who has this IP address? Tell me your MAC address."

The device that owns the IP replies with its **MAC address**.

---

# What is ARP Spoofing?

In an **ARP spoofing attack**, a malicious device sends **fake ARP replies** to trick hosts into believing that:

```
Gateway IP → Attacker MAC
```

This allows attackers to:

- Intercept traffic
- Perform **Man-in-the-Middle attacks**
- Capture credentials
- Modify packets
- Monitor network communication

Because ARP **does not verify authenticity**, devices accept the **latest ARP reply they receive**.

---

# Features

- Real-time packet sniffing
- ARP packet filtering
- Extraction of ARP fields (IP & MAC)
- Detection of IP ↔ MAC mapping changes
- Timestamped alerts
- Lightweight design (`store=False`)
- Modular detection engine
- Clean console logs

---

# Architecture

```
             +----------------------+
             |  Network Interface   |
             |      (eth0)          |
             +----------+-----------+
                        |
                        v
                +---------------+
                | Packet Sniffer|
                |   (Scapy)     |
                +-------+-------+
                        |
                        v
                +---------------+
                | Packet Handler|
                +-------+-------+
                        |
                        v
                +---------------+
                | Detection     |
                | Engine        |
                +-------+-------+
                        |
                        v
                +---------------+
                | Alert System  |
                | Console Logs  |
                +---------------+
```

---

# Detection Logic

The program maintains a **mapping table**:

```
IP Address → MAC Address
```

Each ARP packet is processed as follows:

1. Extract packet fields
2. Check if the IP exists in the table
3. If IP exists but MAC is different
4. Trigger a **spoofing alert**

Example rule:

```
if stored_mac != observed_mac:
    raise alert
```

---

# Execution Flow

```
Program Start
      │
      ▼
main() initializes modules
      │
      ▼
Sniffer starts listening
      │
      ▼
ARP packet received
      │
      ▼
packet_handler() triggered
      │
      ▼
Extract IP + MAC
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
Alert generated if anomaly detected
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/yourusername/arp-spoof-detector.git
cd arp-spoof-detector
```

Install dependencies

```bash
pip install scapy
```

---

# Usage

Run with root privileges (required for packet sniffing)

```bash
sudo python3 main.py
```

Specify interface manually

```bash
sudo python3 main.py -i eth0
```

---

# Example Output

```
[INFO] ARP Reply Captured

Source IP   : 192.168.1.1
Source MAC  : AA:BB:CC:DD:EE:FF

---------------------------------------

[ALERT] Possible ARP Spoofing Detected

IP Address : 192.168.1.1
Old MAC    : AA:BB:CC:DD:EE:FF
New MAC    : 11:22:33:44:55:66
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
├── requirements.txt
└── README.md
```

---

# Future Improvements

Planned improvements include:

- Persistent ARP mapping database
- Logging alerts to files
- Email or Telegram alert system
- GUI dashboard
- Integration with SIEM tools
- Machine learning anomaly detection

---

## ⚠️ Disclaimer

This tool is intended **for educational and defensive cybersecurity purposes only**.

Do **not run it on networks without authorization**.

