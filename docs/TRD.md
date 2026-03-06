# Technical Reference Document (TRD)

## ARP Spoofing Detector

**Document Version:** 1.0.0  
**Date:** 2026-03-06  
**Classification:** Internal / Open Source  
**License:** MIT  
**Author:** Prashant B.  
**Repository:** [Prashant-1490-B/ARP_Spoofing_Detector](https://github.com/Prashant-1490-B/ARP_Spoofing_Detector)

---

## Table of Contents

1. [Document Control](#1-document-control)
2. [Executive Summary](#2-executive-summary)
3. [Scope and Objectives](#3-scope-and-objectives)
4. [Definitions, Acronyms, and Abbreviations](#4-definitions-acronyms-and-abbreviations)
5. [System Overview](#5-system-overview)
6. [Architecture and Design](#6-architecture-and-design)
   - 6.1 [High-Level Architecture](#61-high-level-architecture)
   - 6.2 [Component Diagram](#62-component-diagram)
   - 6.3 [Data Flow Diagram](#63-data-flow-diagram)
   - 6.4 [Module Dependency Graph](#64-module-dependency-graph)
7. [Module Specifications](#7-module-specifications)
   - 7.1 [Entry Point — `main.py`](#71-entry-point--mainpy)
   - 7.2 [Configuration Module — `config.py`](#72-configuration-module--configpy)
   - 7.3 [Core Package — `core/`](#73-core-package--core)
     - 7.3.1 [Packet Sniffer — `core/sniffer.py`](#731-packet-sniffer--coresnifferpy)
     - 7.3.2 [ARP Detection Engine — `core/arp_engine.py`](#732-arp-detection-engine--corearp_enginepy)
     - 7.3.3 [State Manager — `core/state_manager.py`](#733-state-manager--corestate_managerpy)
   - 7.4 [Utilities Package — `utils/`](#74-utilities-package--utils)
     - 7.4.1 [Logger — `utils/logger.py`](#741-logger--utilsloggerpy)
   - 7.5 [Environment Check — `env_check.py`](#75-environment-check--env_checkpy)
   - 7.6 [Test Suite — `tests/`](#76-test-suite--tests)
8. [Detection Algorithms](#8-detection-algorithms)
   - 8.1 [MAC Address Change Detection](#81-mac-address-change-detection)
   - 8.2 [Multi-IP Claiming Detection](#82-multi-ip-claiming-detection)
   - 8.3 [ARP Flood Detection](#83-arp-flood-detection)
9. [Configuration Reference](#9-configuration-reference)
10. [Data Structures and State Model](#10-data-structures-and-state-model)
11. [Interface Contracts and API Reference](#11-interface-contracts-and-api-reference)
12. [Execution Flow](#12-execution-flow)
13. [Deployment and Installation](#13-deployment-and-installation)
    - 13.1 [Prerequisites](#131-prerequisites)
    - 13.2 [Installation Steps](#132-installation-steps)
    - 13.3 [Running the Application](#133-running-the-application)
14. [Logging and Alerting](#14-logging-and-alerting)
15. [Error Handling and Fault Tolerance](#15-error-handling-and-fault-tolerance)
16. [Security Considerations](#16-security-considerations)
17. [Performance Characteristics](#17-performance-characteristics)
18. [Testing](#18-testing)
19. [Project Directory Structure](#19-project-directory-structure)
20. [Dependency Inventory](#20-dependency-inventory)
21. [Known Limitations](#21-known-limitations)
22. [Future Enhancements Roadmap](#22-future-enhancements-roadmap)
23. [Appendix A — Sample Output](#appendix-a--sample-output)
24. [Appendix B — Glossary of ARP Operations](#appendix-b--glossary-of-arp-operations)
25. [Appendix C — Revision History](#appendix-c--revision-history)

---

## 1. Document Control

| Field               | Value                                                      |
|---------------------|------------------------------------------------------------|
| Document Title      | Technical Reference Document — ARP Spoofing Detector       |
| Version             | 1.0.0                                                      |
| Status              | Released                                                   |
| Author              | Prashant B.                                                |
| Reviewed By         | —                                                          |
| Approved By         | —                                                          |
| Creation Date       | 2026-03-06                                                 |
| Last Modified       | 2026-03-06                                                 |
| Distribution        | Public (MIT Licensed)                                      |
| Repository          | `Prashant-1490-B/ARP_Spoofing_Detector`                    |
| Primary Language    | Python 3.x                                                 |
| Runtime Environment | Linux (requires root/sudo privileges)                      |

---

## 2. Executive Summary

The **ARP Spoofing Detector** is a real-time network security monitoring tool built in Python using the Scapy packet manipulation library. It operates as a passive network sensor that continuously captures and analyzes ARP (Address Resolution Protocol) reply packets on a specified network interface.

The system implements three distinct detection heuristics:

1. **MAC Address Change Detection** — Identifies when a previously observed IP address suddenly maps to a different MAC address, a primary indicator of ARP cache poisoning.
2. **Multi-IP Claiming Detection** — Detects when a single MAC address claims ownership of an unusually high number of IP addresses, which may indicate a rogue device attempting to intercept traffic for multiple hosts.
3. **ARP Flood Detection** — Identifies abnormally high volumes of ARP reply traffic from a single source within a configurable time window, a pattern commonly associated with automated ARP spoofing tools.

The tool is designed for deployment on Linux-based systems within local area networks (LANs) and is intended for **defensive cybersecurity** use cases including network monitoring, intrusion detection, and incident response support.

---

## 3. Scope and Objectives

### 3.1 In Scope

- Passive real-time monitoring of ARP reply packets on a local network interface.
- Detection of IP-to-MAC mapping anomalies indicative of ARP spoofing attacks.
- Detection of MAC-to-multi-IP anomalies indicative of traffic interception attempts.
- Detection of ARP reply flooding patterns.
- Timestamped alert logging to both console (stdout) and persistent log files.
- Configurable detection thresholds and parameters.
- Modular, extensible architecture suitable for integration into larger security toolchains.

### 3.2 Out of Scope

- Active ARP spoofing prevention or remediation (e.g., sending corrective ARP packets).
- Deep packet inspection beyond ARP layer fields.
- GUI-based monitoring dashboards.
- Integration with external alerting systems (email, Telegram, SIEM).
- Persistent storage of ARP baselines across application restarts.
- Support for non-Linux operating systems.

### 3.3 Objectives

| ID    | Objective                                                                 | Priority |
|-------|---------------------------------------------------------------------------|----------|
| OBJ-1 | Provide real-time detection of ARP spoofing attacks on local networks    | Critical |
| OBJ-2 | Maintain zero false negatives for direct MAC change spoofing patterns    | High     |
| OBJ-3 | Operate with minimal resource footprint suitable for embedded deployment | High     |
| OBJ-4 | Produce human-readable, timestamped alert logs                           | Medium   |
| OBJ-5 | Support configurable detection sensitivity                               | Medium   |
| OBJ-6 | Enable extensibility through modular component design                    | Medium   |

---

## 4. Definitions, Acronyms, and Abbreviations

| Term / Acronym | Definition |
|----------------|------------|
| **ARP**        | Address Resolution Protocol — Layer 2/3 protocol that maps IPv4 addresses to MAC (hardware) addresses within a local network segment. |
| **ARP Reply**  | An ARP packet with opcode `2`, sent in response to an ARP request or unsolicited (gratuitous ARP). |
| **ARP Request** | An ARP packet with opcode `1`, broadcast to discover the MAC address for a given IP. |
| **ARP Table**  | A mapping of IP addresses to MAC addresses maintained by network hosts. Also called the ARP cache. |
| **ARP Spoofing** | An attack technique where an adversary sends forged ARP messages to associate their MAC address with a victim's IP address. Also known as ARP poisoning or ARP cache poisoning. |
| **Baseline**   | The initial IP → MAC mapping observed by the detector, treated as the legitimate mapping. |
| **Flood**      | An abnormally high volume of ARP packets sent within a short time window. |
| **Gratuitous ARP** | An unsolicited ARP reply sent to update other hosts' ARP caches. May be legitimate or malicious. |
| **LAN**        | Local Area Network — A network covering a small geographic area (e.g., a building or campus). |
| **MAC Address** | Media Access Control address — A unique 48-bit hardware identifier assigned to network interfaces. Represented as six colon-separated hexadecimal octets (e.g., `AA:BB:CC:DD:EE:FF`). |
| **MITM**       | Man-in-the-Middle — An attack where the adversary secretly relays and possibly alters communication between two parties. |
| **NIC**        | Network Interface Card — Hardware component that connects a device to a network. |
| **Scapy**      | A Python-based interactive packet manipulation library used for packet crafting, sniffing, and analysis. |
| **Sniffer**    | A software component that captures network packets from a network interface in promiscuous or monitor mode. |
| **TRD**        | Technical Reference Document — A comprehensive document detailing the technical design, implementation, and operational aspects of a system. |

---

## 5. System Overview

### 5.1 Purpose

The ARP Spoofing Detector serves as a lightweight, passive network intrusion detection sensor focused specifically on ARP-layer attacks. It fills a niche between full-featured IDS/IPS solutions (e.g., Snort, Suricata) and manual network inspection, providing targeted ARP anomaly detection with minimal configuration.

### 5.2 System Context

```
┌───────────────────────────────────────────────────────────────┐
│                     Local Area Network (LAN)                  │
│                                                               │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐  │
│  │ Gateway   │   │ Host A   │   │ Host B   │   │ Attacker │  │
│  │ Router    │   │          │   │          │   │          │  │
│  └─────┬────┘   └─────┬────┘   └─────┬────┘   └─────┬────┘  │
│        │              │              │              │         │
│  ══════╪══════════════╪══════════════╪══════════════╪═══════  │
│        │         Network Segment (Ethernet / Wi-Fi)          │
│        │                                                     │
│        │     ┌───────────────────────────────┐               │
│        └─────┤   Monitoring Host             │               │
│              │   ┌───────────────────────┐   │               │
│              │   │ ARP Spoofing Detector │   │               │
│              │   │  (this application)   │   │               │
│              │   └───────────────────────┘   │               │
│              └───────────────────────────────┘               │
└───────────────────────────────────────────────────────────────┘
```

### 5.3 Technology Stack

| Layer         | Technology                          |
|---------------|-------------------------------------|
| Language      | Python 3.x                          |
| Packet Engine | Scapy (latest stable)               |
| OS            | Linux (Ubuntu, Debian, Kali, etc.)  |
| Privileges    | Root / sudo (required for raw sockets) |
| Logging       | Custom file-based logger            |

---

## 6. Architecture and Design

### 6.1 High-Level Architecture

The system follows a **pipeline architecture** with four logical stages:

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Capture    │───▶│   Filtering  │───▶│  Detection   │───▶│   Alerting   │
│   (Sniffer)  │    │  (ARP Only)  │    │  (Engine)    │    │  (Logger)    │
└─────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
       │                                      │
       │                                      ▼
       │                              ┌──────────────┐
       │                              │    State      │
       │                              │   Manager     │
       └──────────────────────────────└──────────────┘
```

**Design Principles:**

- **Separation of Concerns** — Each module has a single, well-defined responsibility.
- **Dependency Injection** — The engine and state manager are injected into components rather than created internally.
- **Stateful Processing** — The state manager maintains all runtime state, enabling potential serialization or replacement.
- **Passive Monitoring** — The system never transmits packets; it only reads and analyzes.

### 6.2 Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        main.py (Entry Point)                    │
│                                                                 │
│   Instantiates: StateManager, ARPEngine, Sniffer                │
│   Wires dependencies and starts the capture loop                │
└──────────┬──────────────────┬──────────────────┬────────────────┘
           │                  │                  │
           ▼                  ▼                  ▼
┌──────────────────┐ ┌────────────────┐ ┌─────────────────────┐
│   StateManager   │ │   ARPEngine    │ │      Sniffer        │
│ (state_manager.py│ │(arp_engine.py) │ │   (sniffer.py)      │
│                  │ │                │ │                     │
│ • arp_table{}    │ │ • process_     │ │ • packet_handler()  │
│ • mac_ip_map{}   │◀┤   reply()     │◀┤ • start()           │
│ • arp_activity{} │ │                │ │                     │
│                  │ │ Uses:          │ │ Uses:               │
│ • update_        │ │ • StateManager │ │ • ARPEngine         │
│   baseline()     │ │ • Logger       │ │ • Scapy sniff()     │
│ • record_        │ │ • Config       │ │                     │
│   activity()     │ │                │ │                     │
└──────────────────┘ └───────┬────────┘ └─────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐     ┌──────────────────┐
                    │  utils/logger.py│     │    config.py      │
                    │                 │     │                  │
                    │ • log_alert()   │     │ • INTERFACE      │
                    │   → console     │     │ • LOG_FILE       │
                    │   → file        │     │ • ALERT_THRESHOLD│
                    └─────────────────┘     │ • FLOOD_WINDOW   │
                                            │ • FLOOD_LIMIT    │
                                            └──────────────────┘
```

### 6.3 Data Flow Diagram

```
                    Network Wire
                         │
                         ▼
              ┌─────────────────────┐
              │  Raw Ethernet Frame │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Scapy sniff()      │  Capture Layer
              │  iface = "eth0"     │
              │  store = False      │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  packet_handler()   │  Filter Layer
              │                     │
              │  Has ARP layer?─No──┼──▶ [Discard]
              │       │ Yes         │
              │       ▼             │
              │  op == 2 (Reply)?   │
              │       │ Yes    No───┼──▶ [Discard]
              └───────┬─────────────┘
                      │
                      ▼
              ┌─────────────────────┐
              │  Extract Fields     │  Extraction Layer
              │  • psrc  (Source IP)│
              │  • hwsrc (Src MAC)  │
              └───────┬─────────────┘
                      │
                      ▼
              ┌─────────────────────┐
              │  engine.process_    │  Detection Layer
              │  reply(ip, mac)     │
              │                     │
              │  ┌────────────────┐ │
              │  │ Baseline Check │ │
              │  │ (NEW → store)  │ │
              │  └───────┬────────┘ │
              │          │ EXISTS   │
              │  ┌───────▼────────┐ │
              │  │ MAC Change?    │ │
              │  │ threshold ≥ 3  │─┼──▶ ALERT: Spoofing
              │  └───────┬────────┘ │
              │  ┌───────▼────────┐ │
              │  │ Multi-IP?      │ │
              │  │ IPs > 2        │─┼──▶ ALERT: Multi-IP
              │  └───────┬────────┘ │
              │  ┌───────▼────────┐ │
              │  │ Flood?         │ │
              │  │ replies ≥ 10   │─┼──▶ ALERT: Flooding
              │  │ in 10 seconds  │ │
              │  └────────────────┘ │
              └─────────────────────┘
```

### 6.4 Module Dependency Graph

```
main.py
  ├── config.py
  ├── core/sniffer.py
  │     └── scapy.all (sniff, ARP)
  ├── core/arp_engine.py
  │     ├── config.py (ALERT_THRESHOLD, FLOOD_WINDOW, FLOOD_LIMIT)
  │     ├── utils/logger.py (log_alert)
  │     └── datetime (timedelta)
  └── core/state_manager.py
        ├── collections (defaultdict)
        └── datetime (datetime)
```

---

## 7. Module Specifications

### 7.1 Entry Point — `main.py`

| Attribute       | Value                                     |
|-----------------|-------------------------------------------|
| File            | `main.py`                                 |
| Purpose         | Application entry point and dependency wiring |
| Lines of Code   | 15                                        |
| Imports         | `config`, `core.sniffer`, `core.arp_engine`, `core.state_manager` |
| Execution       | `sudo python3 main.py`                    |

**Responsibilities:**

1. Import configuration constants (`INTERFACE`, `LOG_FILE`).
2. Instantiate the `StateManager` (runtime state container).
3. Instantiate the `ARPEngine` with the state manager and log file path.
4. Instantiate the `Sniffer` with the network interface and engine reference.
5. Start the packet capture loop via `sniffer.start()`.

**Source Code Analysis:**

```python
from config import INTERFACE, LOG_FILE
from core.sniffer import Sniffer
from core.arp_engine import ARPEngine
from core.state_manager import StateManager

def main():
    state_manager = StateManager()
    engine = ARPEngine(state_manager, LOG_FILE)
    sniffer = Sniffer(INTERFACE, engine)
    sniffer.start()

if __name__ == "__main__":
    main()
```

**Initialization Sequence Diagram:**

```
main()
  │
  ├─▶ StateManager()          # Empty ARP table, maps, activity lists
  │       │
  ├─▶ ARPEngine(state, log)   # Links state + log file
  │       │
  ├─▶ Sniffer(iface, engine)  # Links interface + engine
  │       │
  └─▶ sniffer.start()         # Blocking call — enters sniff loop
```

---

### 7.2 Configuration Module — `config.py`

| Attribute       | Value                          |
|-----------------|--------------------------------|
| File            | `config.py`                    |
| Purpose         | Centralized application configuration constants |
| Lines of Code   | 6                              |
| Dependencies    | None (pure constants)          |

**Configuration Parameters:**

| Constant          | Type   | Default Value       | Description |
|-------------------|--------|---------------------|-------------|
| `INTERFACE`       | `str`  | `"eth0"`            | Network interface to monitor. Must be a valid NIC name available on the host system. |
| `LOG_FILE`        | `str`  | `"../logs/alerts.log"` | Relative path to the alert log file. Parent directories are created automatically by the logger. |
| `ALERT_THRESHOLD` | `int`  | `3`                 | Number of consecutive MAC address changes for a given IP before a spoofing alert is triggered. Prevents false positives from transient network events. |
| `FLOOD_WINDOW`    | `int`  | `10`                | Time window in seconds used for ARP flood detection. ARP replies within this window are counted. |
| `FLOOD_LIMIT`     | `int`  | `10`                | Maximum number of ARP replies allowed from a single IP within `FLOOD_WINDOW` seconds before a flood alert is raised. |

**Configuration Tuning Guidelines:**

| Scenario                              | Recommended Change                           |
|---------------------------------------|----------------------------------------------|
| High false-positive rate              | Increase `ALERT_THRESHOLD` to 5–10           |
| Missing low-volume spoofing attacks   | Decrease `ALERT_THRESHOLD` to 1–2            |
| Large network with heavy ARP traffic  | Increase `FLOOD_LIMIT` to 20–50              |
| Detecting rapid spoofing bursts       | Decrease `FLOOD_WINDOW` to 3–5 seconds       |
| Monitoring Wi-Fi interface            | Change `INTERFACE` to `wlan0` or equivalent  |

---

### 7.3 Core Package — `core/`

The `core` package contains the three primary runtime modules. The package is initialized via an empty `__init__.py`.

#### 7.3.1 Packet Sniffer — `core/sniffer.py`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| File            | `core/sniffer.py`                          |
| Purpose         | Network packet capture and initial filtering |
| Lines of Code   | 18 (active)                                |
| Class           | `Sniffer`                                  |
| Dependencies    | `scapy.all.sniff`, `scapy.all.ARP`         |

**Class: `Sniffer`**

| Method            | Parameters                    | Return Type | Description |
|-------------------|-------------------------------|-------------|-------------|
| `__init__`        | `interface: str`, `engine: ARPEngine` | `None` | Stores the network interface name and a reference to the detection engine. |
| `packet_handler`  | `packet: scapy.packet.Packet` | `None`      | Callback invoked by Scapy for each captured packet. Filters for ARP reply packets (opcode 2) and delegates to the engine. |
| `start`           | (none)                        | `None`      | Initiates the blocking Scapy `sniff()` loop on the configured interface with `store=False` for memory efficiency. |

**Packet Filtering Logic:**

```
Incoming Packet
      │
      ▼
  Has ARP layer? ──No──▶ [Ignored]
      │ Yes
      ▼
  ARP opcode == 2? ──No──▶ [Ignored]
      │ Yes
      ▼
  Extract: psrc (Source IP), hwsrc (Source MAC)
      │
      ▼
  engine.process_reply(ip, mac)
```

**Key Design Decisions:**

- **`store=False`**: Prevents Scapy from accumulating packets in memory, ensuring the tool can run indefinitely without memory exhaustion.
- **Opcode 2 filter**: Only ARP replies are analyzed. ARP requests (opcode 1) are ignored because spoofing attacks primarily operate via forged replies.
- **Callback pattern**: Uses Scapy's `prn` (print) callback parameter for event-driven processing.

---

#### 7.3.2 ARP Detection Engine — `core/arp_engine.py`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| File            | `core/arp_engine.py`                       |
| Purpose         | Core detection logic — evaluates ARP packets against multiple heuristic rules |
| Lines of Code   | 53                                         |
| Class           | `ARPEngine`                                |
| Dependencies    | `datetime.timedelta`, `config`, `utils.logger` |

**Class: `ARPEngine`**

| Method           | Parameters                           | Return Type | Description |
|------------------|--------------------------------------|-------------|-------------|
| `__init__`       | `state_manager: StateManager`, `log_file: str` | `None` | Stores references to the state manager and log file path. |
| `process_reply`  | `ip: str`, `mac: str`               | `None`      | Main detection method. Evaluates the ARP reply against all three detection heuristics. |

**`process_reply()` — Detailed Logic Flow:**

```
process_reply(ip, mac)
│
├─▶ state.update_baseline(ip, mac)
│       │
│       ├── Returns "NEW"  ──▶ Print baseline, RETURN
│       │
│       └── Returns "EXISTS" ──▶ Continue
│
├─▶ DETECTION 1: MAC Change
│       │
│       ├── mac != known_mac?
│       │       │ Yes
│       │       ├── Increment suspicious_count
│       │       └── suspicious_count >= ALERT_THRESHOLD?
│       │               │ Yes
│       │               └── log_alert("[ALERT] ARP Spoofing suspected!")
│       │
│       └── mac == known_mac?
│               └── Reset suspicious_count to 0
│
├─▶ DETECTION 2: Multi-IP Claiming
│       │
│       ├── Add ip to mac_ip_map[mac]
│       └── len(mac_ip_map[mac]) > 2?
│               │ Yes
│               └── log_alert("[ALERT] MAC claiming multiple IPs")
│
└─▶ DETECTION 3: ARP Flood
        │
        ├── Record activity timestamp
        ├── Filter recent activity within FLOOD_WINDOW
        └── len(recent) >= FLOOD_LIMIT?
                │ Yes
                └── log_alert("[ALERT] ARP Flooding suspected")
```

**Detection Rule Specifications:**

| Rule ID | Rule Name          | Trigger Condition                                                     | Severity | Alert Message Pattern |
|---------|--------------------|-----------------------------------------------------------------------|----------|-----------------------|
| DET-001 | MAC Change         | `suspicious_count >= ALERT_THRESHOLD` (default: 3)                    | High     | `[ALERT] ARP Spoofing suspected! IP: {ip}, Old MAC: {old}, New MAC: {new}` |
| DET-002 | Multi-IP Claiming  | Single MAC mapped to > 2 distinct IPs                                 | High     | `[ALERT] MAC {mac} claiming multiple IPs: {ip_list}` |
| DET-003 | ARP Flooding       | ≥ `FLOOD_LIMIT` (default: 10) ARP replies from one IP within `FLOOD_WINDOW` (default: 10s) | Medium   | `[ALERT] ARP Flooding suspected from IP: {ip}` |

---

#### 7.3.3 State Manager — `core/state_manager.py`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| File            | `core/state_manager.py`                    |
| Purpose         | Centralized runtime state storage for ARP observations |
| Lines of Code   | 29                                         |
| Class           | `StateManager`                             |
| Dependencies    | `collections.defaultdict`, `datetime.datetime` |

**Class: `StateManager`**

| Method             | Parameters               | Return Type        | Description |
|--------------------|--------------------------|--------------------|-------------|
| `__init__`         | (none)                   | `None`             | Initializes all state data structures to empty containers. |
| `update_baseline`  | `ip: str`, `mac: str`    | `str` (`"NEW"` or `"EXISTS"`) | Registers a new IP-MAC mapping or indicates that the IP already exists in the baseline. |
| `record_activity`  | `ip: str`                | `datetime.datetime` | Appends the current timestamp to the activity log for the given IP and returns the timestamp. |

**Data Structures:**

| Attribute       | Type                          | Key       | Value                                          | Purpose |
|-----------------|-------------------------------|-----------|------------------------------------------------|---------|
| `arp_table`     | `dict[str, dict]`             | IP address | `{"mac": str, "first_seen": datetime, "last_seen": datetime, "suspicious_count": int}` | Primary ARP baseline table. Stores the first-observed MAC for each IP along with metadata. |
| `mac_ip_map`    | `defaultdict(set)`            | MAC address | `set` of IP addresses                          | Reverse mapping used to detect a single MAC claiming multiple IPs. |
| `arp_activity`  | `defaultdict(list)`           | IP address | `list` of `datetime` timestamps                | Activity log used for flood detection. Records the timestamp of each ARP reply per IP. |

**ARP Table Entry Schema:**

```python
{
    "mac": "AA:BB:CC:DD:EE:FF",     # First observed MAC address
    "first_seen": datetime(2026, 3, 6, 10, 0, 0),  # Timestamp of first observation
    "last_seen": datetime(2026, 3, 6, 10, 0, 0),    # Timestamp of entry creation
    "suspicious_count": 0            # Counter for consecutive MAC changes
}
```

**State Lifecycle:**

```
Application Start
      │
      ▼
  All structures empty:
    arp_table = {}
    mac_ip_map = defaultdict(set)
    arp_activity = defaultdict(list)
      │
      ▼
  First ARP reply for IP X:
    arp_table[X] = {mac, timestamps, count=0}
    Returns "NEW"
      │
      ▼
  Subsequent ARP reply for IP X:
    Returns "EXISTS"
    Engine checks mac_ip_map and arp_activity
      │
      ▼
  Application Termination:
    All state lost (in-memory only)
```

---

### 7.4 Utilities Package — `utils/`

#### 7.4.1 Logger — `utils/logger.py`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| File            | `utils/logger.py`                          |
| Purpose         | Dual-output alert logging (console + file) |
| Lines of Code   | 14                                         |
| Dependencies    | `datetime.datetime`, `os`                  |

**Function: `log_alert`**

| Parameter  | Type   | Description                                           |
|------------|--------|-------------------------------------------------------|
| `message`  | `str`  | The alert message to log.                              |
| `log_file` | `str`  | File path for persistent log output. Parent directories are created automatically. |

**Behavior:**

1. Generate a timestamp string in `YYYY-MM-DD HH:MM:SS` format.
2. Format the log entry as `[{timestamp}] {message}\n`.
3. Create parent directories for `log_file` if they do not exist (`os.makedirs` with `exist_ok=True`).
4. Append the log entry to the file.
5. Print the log entry to stdout.

**Log Entry Format:**

```
[2026-03-06 14:23:45] [ALERT] ARP Spoofing suspected! IP: 192.168.1.1, Old MAC: AA:BB:CC:DD:EE:FF, New MAC: 11:22:33:44:55:66
```

---

### 7.5 Environment Check — `env_check.py`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| File            | `env_check.py`                             |
| Purpose         | Diagnostic utility to verify Scapy and NIC functionality |
| Lines of Code   | 12                                         |
| Dependencies    | `scapy.all.sniff`, `scapy.all.ARP`, `os`  |

**Behavior:**

1. Prints `[+] Enviornment Check` to stdout.
2. Captures a single packet using `sniff(count=1)`.
3. If the packet contains an ARP layer, prints `[+] Packet Captured`.
4. Exits after capturing one ARP packet.

**Usage:**

```bash
sudo python3 env_check.py
```

This utility is intended for pre-deployment validation to confirm that:
- Scapy is correctly installed.
- The host has raw socket permissions.
- The network interface is active and receiving ARP traffic.

---

### 7.6 Test Suite — `tests/`

| Attribute       | Value                                      |
|-----------------|--------------------------------------------|
| Directory       | `tests/`                                   |
| Purpose         | Detection validation and integration testing |
| Test File       | `tests/test_detection.py`                  |
| Framework       | Manual packet injection via Scapy          |

**`test_detection.py`** contains:

1. **Active test** — Constructs and sends a crafted ARP reply packet on `eth0` using `sendp()`. This is an integration test that requires the main detector to be running simultaneously.
2. **Commented unit tests** — Contains commented-out unit test functions (`test_baseline`, `test_mac_change`) that directly instantiate `StateManager` and `ARPEngine` for isolated logic testing.

**Crafted Test Packet:**

```python
Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,                          # ARP Reply
    psrc="192.168.1.1",            # Spoofed source IP
    hwsrc="aa:bb:cc:dd:ee:ff",     # Spoofed source MAC
    pdst="192.168.1.200"           # Target IP
)
```

---

## 8. Detection Algorithms

### 8.1 MAC Address Change Detection

**Algorithm ID:** DET-001  
**Purpose:** Detect ARP cache poisoning via IP-to-MAC remapping.

**Pseudocode:**

```
FUNCTION process_mac_change(ip, observed_mac):
    known_mac ← arp_table[ip]["mac"]
    
    IF observed_mac ≠ known_mac THEN
        arp_table[ip]["suspicious_count"] += 1
        
        IF arp_table[ip]["suspicious_count"] ≥ ALERT_THRESHOLD THEN
            RAISE ALERT "ARP Spoofing suspected"
                WITH ip, known_mac, observed_mac
        END IF
    ELSE
        arp_table[ip]["suspicious_count"] ← 0  // Reset on normal reply
    END IF
END FUNCTION
```

**Analysis:**

- The threshold mechanism (`ALERT_THRESHOLD = 3`) prevents false positives from legitimate MAC changes (e.g., NIC replacement, VM migration).
- The counter resets to 0 upon receiving a matching (legitimate) MAC, implementing a "consecutive changes" model.
- **Note:** The baseline MAC (`known_mac`) is never updated after initial observation, meaning a legitimate MAC change will permanently elevate the suspicious count until a matching reply is received.

### 8.2 Multi-IP Claiming Detection

**Algorithm ID:** DET-002  
**Purpose:** Detect a single MAC address impersonating multiple network hosts.

**Pseudocode:**

```
FUNCTION process_multi_ip(ip, mac):
    mac_ip_map[mac].ADD(ip)
    
    IF |mac_ip_map[mac]| > 2 THEN
        RAISE ALERT "MAC claiming multiple IPs"
            WITH mac, mac_ip_map[mac]
    END IF
END FUNCTION
```

**Analysis:**

- A threshold of 2 IPs is used because a legitimate device may respond for both its own IP and the gateway IP in certain configurations.
- The set-based storage ensures duplicate IP additions are idempotent.
- **Note:** This rule triggers on every subsequent ARP reply once the threshold is exceeded, since the set size never decreases.

### 8.3 ARP Flood Detection

**Algorithm ID:** DET-003  
**Purpose:** Detect automated ARP spoofing tools that generate high volumes of forged replies.

**Pseudocode:**

```
FUNCTION process_flood(ip):
    now ← CURRENT_TIMESTAMP
    arp_activity[ip].APPEND(now)
    
    recent ← FILTER(arp_activity[ip], 
                     WHERE now - timestamp < FLOOD_WINDOW seconds)
    
    IF |recent| ≥ FLOOD_LIMIT THEN
        RAISE ALERT "ARP Flooding suspected"
            WITH ip
    END IF
END FUNCTION
```

**Analysis:**

- Uses a sliding time window approach rather than fixed time buckets.
- The activity list grows unboundedly since old entries are never pruned — only filtered at query time.
- **Note:** For long-running deployments, the `arp_activity` list will accumulate all historical timestamps. This is a known memory consideration (see [Section 21 — Known Limitations](#21-known-limitations)).

---

## 9. Configuration Reference

Complete configuration parameter reference with validation constraints:

| Parameter         | Type  | Default            | Valid Range         | Environment   | Description |
|-------------------|-------|--------------------|---------------------|---------------|-------------|
| `INTERFACE`       | `str` | `"eth0"`           | Valid NIC name      | Linux         | Network interface for packet capture. Must exist and be active. |
| `LOG_FILE`        | `str` | `"../logs/alerts.log"` | Valid file path | Linux FS      | Path for alert log file. Relative to working directory. Parent directories auto-created. |
| `ALERT_THRESHOLD` | `int` | `3`                | `≥ 1`               | —             | Consecutive MAC change count before spoofing alert fires. |
| `FLOOD_WINDOW`    | `int` | `10`               | `≥ 1` (seconds)     | —             | Time window for ARP flood detection. |
| `FLOOD_LIMIT`     | `int` | `10`               | `≥ 1`               | —             | ARP reply count threshold within the flood window. |

---

## 10. Data Structures and State Model

### 10.1 Runtime State Summary

```
StateManager
│
├── arp_table: dict
│       Key: str (IP address, e.g., "192.168.1.1")
│       Value: dict
│           ├── "mac": str             (e.g., "AA:BB:CC:DD:EE:FF")
│           ├── "first_seen": datetime (initial observation timestamp)
│           ├── "last_seen": datetime  (entry creation timestamp)
│           └── "suspicious_count": int (consecutive MAC changes)
│
├── mac_ip_map: defaultdict(set)
│       Key: str (MAC address)
│       Value: set of str (IP addresses claimed by this MAC)
│
└── arp_activity: defaultdict(list)
        Key: str (IP address)
        Value: list of datetime (timestamps of ARP replies)
```

### 10.2 State Transition Model for `arp_table` Entries

```
                       ┌──────────────┐
                       │   [Empty]    │
                       └──────┬───────┘
                              │ First ARP reply
                              │ for this IP
                              ▼
                       ┌──────────────┐
                       │   BASELINE   │
                       │ count = 0    │
                       └──────┬───────┘
                              │
               ┌──────────────┴──────────────┐
               │                             │
        Same MAC reply                Different MAC reply
               │                             │
               ▼                             ▼
        ┌──────────────┐             ┌──────────────┐
        │   NORMAL     │             │  SUSPICIOUS  │
        │ count ← 0    │             │ count += 1   │
        └──────┬───────┘             └──────┬───────┘
               │                             │
               │                     count ≥ THRESHOLD?
               │                      │ Yes        │ No
               │                      ▼            │
               │              ┌──────────────┐     │
               │              │   ALERTED    │     │
               │              │ Alert fired  │     │
               │              └──────────────┘     │
               │                                   │
               └───────────────────────────────────┘
                         (cycle continues)
```

---

## 11. Interface Contracts and API Reference

### 11.1 `StateManager` Interface

```python
class StateManager:
    """Centralized runtime state container for ARP observations."""

    arp_table: dict[str, dict]
    """IP → {mac, first_seen, last_seen, suspicious_count}"""

    mac_ip_map: defaultdict[str, set[str]]
    """MAC → set of IPs"""

    arp_activity: defaultdict[str, list[datetime]]
    """IP → list of activity timestamps"""

    def update_baseline(self, ip: str, mac: str) -> str:
        """
        Register or check an IP-MAC pair.

        Args:
            ip: Source IP address from ARP reply.
            mac: Source MAC address from ARP reply.

        Returns:
            "NEW" if the IP was not previously observed.
            "EXISTS" if the IP already has a baseline entry.
        """

    def record_activity(self, ip: str) -> datetime:
        """
        Record an ARP reply event for flood detection.

        Args:
            ip: Source IP address from ARP reply.

        Returns:
            The current datetime timestamp.
        """
```

### 11.2 `ARPEngine` Interface

```python
class ARPEngine:
    """Core detection engine implementing ARP anomaly heuristics."""

    def __init__(self, state_manager: StateManager, log_file: str) -> None:
        """
        Args:
            state_manager: Shared state container instance.
            log_file: Path for persistent alert logging.
        """

    def process_reply(self, ip: str, mac: str) -> None:
        """
        Process a single ARP reply through all detection rules.

        Args:
            ip: Source IP address extracted from ARP reply (psrc).
            mac: Source MAC address extracted from ARP reply (hwsrc).

        Side Effects:
            - Updates state_manager.arp_table
            - Updates state_manager.mac_ip_map
            - Updates state_manager.arp_activity
            - May invoke log_alert() for any triggered rules
        """
```

### 11.3 `Sniffer` Interface

```python
class Sniffer:
    """Network packet capture and ARP reply extraction."""

    def __init__(self, interface: str, engine: ARPEngine) -> None:
        """
        Args:
            interface: Network interface name (e.g., "eth0").
            engine: Detection engine to receive extracted ARP data.
        """

    def packet_handler(self, packet: scapy.packet.Packet) -> None:
        """
        Scapy callback for each captured packet.

        Filters for ARP reply packets (opcode == 2) and
        delegates source IP/MAC to the engine.
        """

    def start(self) -> None:
        """
        Begin the blocking packet capture loop.

        This method does not return under normal operation.
        Uses store=False for memory-efficient continuous capture.
        """
```

### 11.4 `log_alert` Interface

```python
def log_alert(message: str, log_file: str) -> None:
    """
    Write a timestamped alert to both console and file.

    Args:
        message: Alert text (e.g., "[ALERT] ARP Spoofing suspected...").
        log_file: Path to the log file. Parent directories are created
                  automatically if they do not exist.

    Side Effects:
        - Appends formatted entry to log_file.
        - Prints formatted entry to stdout.
    """
```

---

## 12. Execution Flow

### 12.1 Application Lifecycle

```
┌────────────────────────────────────────────────────────┐
│                    STARTUP PHASE                       │
│                                                        │
│  1. Python interpreter loads main.py                   │
│  2. config.py constants imported                       │
│  3. StateManager instantiated (empty state)            │
│  4. ARPEngine instantiated (linked to state + logger)  │
│  5. Sniffer instantiated (linked to interface + engine) │
│  6. sniffer.start() called                             │
│  7. "[+] Listening on eth0" printed to console         │
│  8. Scapy sniff() loop begins (BLOCKING)               │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│                   RUNTIME PHASE (Loop)                 │
│                                                        │
│  FOR EACH captured packet:                             │
│    1. packet_handler(packet) invoked by Scapy          │
│    2. Check: packet.haslayer(ARP)?                     │
│       └── No → return (ignore)                         │
│    3. Check: arp.op == 2?                              │
│       └── No → return (ignore)                         │
│    4. Extract: ip = arp.psrc, mac = arp.hwsrc          │
│    5. engine.process_reply(ip, mac)                    │
│       a. Baseline check (NEW / EXISTS)                 │
│       b. MAC change detection                          │
│       c. Multi-IP detection                            │
│       d. Flood detection                               │
│    6. Alerts logged if thresholds exceeded             │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│                  SHUTDOWN PHASE                         │
│                                                        │
│  Triggered by: Ctrl+C (SIGINT) or SIGTERM              │
│  1. Scapy sniff() loop interrupted                     │
│  2. Python interpreter exits                           │
│  3. All in-memory state is lost                        │
└────────────────────────────────────────────────────────┘
```

### 12.2 Single Packet Processing Timeline

```
Time ──────────────────────────────────────────────────────────▶

  │ Packet    │ Filter    │ Extract   │ Baseline  │ Detection │ Alert
  │ Captured  │ Applied   │ Fields    │ Check     │ Rules     │ (if any)
  │           │           │           │           │           │
  t₀          t₁          t₂          t₃          t₄          t₅
  │           │           │           │           │           │
  │◄─ ~μs ──▶│◄─ ~μs ──▶│◄─ ~μs ──▶│◄─ ~μs ──▶│◄─ ~μs ──▶│
```

---

## 13. Deployment and Installation

### 13.1 Prerequisites

| Requirement          | Details                                         |
|----------------------|-------------------------------------------------|
| Operating System     | Linux (Ubuntu 18.04+, Debian 10+, Kali Linux)   |
| Python Version       | 3.6 or higher (3.8+ recommended)                |
| System Privileges    | Root / sudo (required for raw socket access)     |
| Network Interface    | Active Ethernet or Wi-Fi NIC                     |
| Package Manager      | `pip` (Python package installer)                 |

### 13.2 Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/Prashant-1490-B/ARP_Spoofing_Detector.git
cd ARP_Spoofing_Detector

# 2. (Recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify environment (optional)
sudo python3 env_check.py

# 5. Configure network interface (if not eth0)
# Edit config.py and set INTERFACE to your NIC name
# Find available interfaces:
ip link show
```

### 13.3 Running the Application

```bash
# Standard execution (requires root)
sudo python3 main.py

# With virtual environment
sudo .venv/bin/python3 main.py

# Background execution with logging
sudo python3 main.py > /var/log/arp_detector_stdout.log 2>&1 &
```

### 13.4 Verifying Operation

After starting the detector, you should see:

```
[+] Listening on eth0
```

To generate test ARP traffic (from another terminal):

```bash
sudo python3 tests/test_detection.py
```

---

## 14. Logging and Alerting

### 14.1 Log Output Channels

| Channel  | Destination              | Format                                 | Persistence |
|----------|--------------------------|----------------------------------------|-------------|
| Console  | stdout                   | `[YYYY-MM-DD HH:MM:SS] {message}\n`   | No (session only) |
| File     | `LOG_FILE` (configurable) | `[YYYY-MM-DD HH:MM:SS] {message}\n`  | Yes (append mode) |

### 14.2 Alert Categories

| Alert Type            | Prefix                        | Trigger                                    | Example |
|-----------------------|-------------------------------|--------------------------------------------|---------|
| Baseline Registration | `[BASELINE]`                  | First ARP reply observed for an IP         | `[BASELINE] 192.168.1.1 → AA:BB:CC:DD:EE:FF` |
| Spoofing Detection    | `[ALERT] ARP Spoofing`        | MAC change count ≥ `ALERT_THRESHOLD`       | `[ALERT] ARP Spoofing suspected! IP: 192.168.1.1, Old MAC: AA:BB:CC:DD:EE:FF, New MAC: 11:22:33:44:55:66` |
| Multi-IP Detection    | `[ALERT] MAC ... multiple`    | Single MAC claims > 2 IPs                  | `[ALERT] MAC 11:22:33:44:55:66 claiming multiple IPs: ['192.168.1.1', '192.168.1.2', '192.168.1.3']` |
| Flood Detection       | `[ALERT] ARP Flooding`        | ≥ `FLOOD_LIMIT` replies within `FLOOD_WINDOW` | `[ALERT] ARP Flooding suspected from IP: 192.168.1.1` |

### 14.3 Sample Log File

```
[2026-03-06 14:23:41] [ALERT] ARP Spoofing suspected! IP: 192.168.1.1, Old MAC: AA:BB:CC:DD:EE:FF, New MAC: 11:22:33:44:55:66
[2026-03-06 14:23:42] [ALERT] MAC 11:22:33:44:55:66 claiming multiple IPs: ['192.168.1.1', '192.168.1.5', '192.168.1.10']
[2026-03-06 14:23:45] [ALERT] ARP Flooding suspected from IP: 192.168.1.1
```

---

## 15. Error Handling and Fault Tolerance

### 15.1 Current Error Handling

The current implementation has minimal explicit error handling. The following failure scenarios and their behaviors are documented:

| Scenario                              | Behavior                                                  | Severity |
|---------------------------------------|-----------------------------------------------------------|----------|
| Invalid network interface             | Scapy raises `OSError` / `Scapy_Exception`; application crashes | Critical |
| Insufficient privileges (non-root)    | Scapy raises `PermissionError`; application crashes        | Critical |
| Log file directory not writable       | `OSError` from `os.makedirs()` or `open()`; alert lost    | High     |
| Network interface goes down           | Scapy `sniff()` may raise exception or return silently     | High     |
| Malformed ARP packet                  | Scapy parses best-effort; may extract unexpected values    | Low      |
| Memory exhaustion (long runtime)      | `arp_activity` list grows unbounded; OOM possible          | Medium   |

### 15.2 Recommended Error Handling Improvements

| Area                | Recommendation                                                |
|---------------------|---------------------------------------------------------------|
| Startup Validation  | Verify interface exists and is active before starting sniff.  |
| Permission Check    | Check for root privileges at startup with a clear error message. |
| Graceful Shutdown   | Add `SIGINT`/`SIGTERM` handlers for clean state reporting.    |
| Log File Safety     | Wrap file operations in try/except to prevent alert loss.     |
| Memory Management   | Periodically prune old entries from `arp_activity`.           |
| Interface Recovery  | Implement retry logic if the NIC temporarily goes down.       |

---

## 16. Security Considerations

### 16.1 Operational Security

| Consideration                   | Details |
|---------------------------------|---------|
| Privilege Level                 | Requires root access for raw socket operations. The principle of least privilege suggests running in a dedicated user namespace or container if possible. |
| Passive Operation               | The tool never transmits packets. It cannot be detected by network scans and does not alter network state. |
| Log File Sensitivity            | Alert logs may contain IP and MAC addresses of network devices. Protect log files with appropriate filesystem permissions (`chmod 600`). |
| State Volatility                | All state is in-memory. No sensitive data persists to disk beyond log entries. |
| No Authentication               | The tool has no authentication mechanism. Access is controlled by OS-level file permissions and sudo policy. |

### 16.2 Attack Surface

| Vector                          | Risk | Mitigation |
|---------------------------------|------|------------|
| Log injection via crafted MACs  | Low  | MAC addresses are extracted by Scapy from binary frames; injection is unlikely but log sanitization is recommended. |
| Resource exhaustion              | Medium | Unbounded `arp_activity` lists could be exploited by flooding ARP traffic. Implement memory limits. |
| Evasion via slow-rate spoofing  | Medium | Attackers sending MAC changes below the `ALERT_THRESHOLD` rate will not trigger alerts. Lower the threshold for higher sensitivity. |

### 16.3 Disclaimer

> **This tool is intended for educational and defensive cybersecurity purposes only.**  
> **Do not run it on networks without authorization.**

---

## 17. Performance Characteristics

### 17.1 Resource Profile

| Resource        | Characteristic                                              |
|-----------------|-------------------------------------------------------------|
| CPU             | Minimal — event-driven callback model; processes only ARP reply packets. |
| Memory (Idle)   | ~20–30 MB (Python interpreter + Scapy library).             |
| Memory (Active) | Grows linearly with unique IPs observed and ARP activity volume. |
| Disk I/O        | Append-only writes to log file on alert events.             |
| Network I/O     | Read-only (passive sniffing); zero transmitted packets.     |

### 17.2 Scalability Considerations

| Factor               | Impact                                                    |
|----------------------|-----------------------------------------------------------|
| Network Size         | More unique IPs → larger `arp_table` and `mac_ip_map`.     |
| Traffic Volume       | Higher ARP rate → faster growth of `arp_activity` lists.   |
| Runtime Duration     | Longer uptime → more accumulated activity timestamps.      |
| Concurrent Attackers | Multiple spoofing sources increase detection load linearly. |

### 17.3 Memory Growth Model

```
Memory ≈ Base + (N_ips × entry_size) + (N_replies × timestamp_size)

Where:
  Base           ≈ 25 MB (Python + Scapy)
  N_ips          = Number of unique IPs observed
  entry_size     ≈ 200 bytes per ARP table entry
  N_replies      = Total ARP replies captured (cumulative)
  timestamp_size ≈ 64 bytes per datetime object
```

---

## 18. Testing

### 18.1 Test Infrastructure

| Component              | Details                                          |
|------------------------|--------------------------------------------------|
| Test Directory         | `tests/`                                         |
| Active Test File       | `tests/test_detection.py`                        |
| Test Type              | Integration (packet injection) + Unit (commented) |
| Framework              | Manual / Scapy `sendp()`                         |
| Requires Running App   | Yes (for integration test)                        |
| Requires Root          | Yes (for packet injection)                        |

### 18.2 Running Tests

**Integration Test (requires detector running in separate terminal):**

```bash
# Terminal 1: Start the detector
sudo python3 main.py

# Terminal 2: Inject test packets
sudo python3 tests/test_detection.py
```

**Commented Unit Tests (can be enabled):**

The file contains commented-out unit tests that can be activated by uncommenting:

- `test_baseline()` — Verifies that a new IP is correctly added to the ARP table.
- `test_mac_change()` — Verifies that MAC changes increment the suspicious count and multi-IP detection works.

### 18.3 Test Coverage Matrix

| Detection Rule         | Test Case Available | Test Type    | Status     |
|------------------------|---------------------|--------------|------------|
| Baseline Registration  | Yes (commented)     | Unit         | Inactive   |
| MAC Change Detection   | Yes (commented)     | Unit         | Inactive   |
| Multi-IP Detection     | Partial (commented) | Unit         | Inactive   |
| Flood Detection        | No                  | —            | Not covered |
| End-to-End Packet Flow | Yes                 | Integration  | Active     |

---

## 19. Project Directory Structure

```
ARP_Spoofing_Detector/
│
├── main.py                    # Application entry point
├── config.py                  # Configuration constants
├── env_check.py               # Environment validation utility
├── requirements.txt           # Python dependencies (scapy)
├── LICENSE                    # MIT License
├── README.md                  # Project documentation
├── .gitignore                 # Git ignore rules
│
├── core/                      # Core detection modules
│   ├── __init__.py            # Package initializer
│   ├── sniffer.py             # Packet capture and filtering
│   ├── arp_engine.py          # Detection heuristics engine
│   └── state_manager.py       # Runtime state management
│
├── utils/                     # Utility modules
│   ├── __init__.py            # Package initializer
│   └── logger.py              # Dual-output alert logger
│
├── tests/                     # Test suite
│   ├── __init__.py            # Package initializer
│   └── test_detection.py      # Detection test cases
│
├── docs/                      # Documentation
│   └── TRD.md                 # This document
│
└── logs/                      # Runtime log output (auto-created)
    └── alerts.log             # Alert log file (generated at runtime)
```

---

## 20. Dependency Inventory

### 20.1 Runtime Dependencies

| Package | Version   | License    | Purpose                                   | PyPI Link |
|---------|-----------|------------|-------------------------------------------|-----------|
| Scapy   | Latest    | GPL-2.0    | Packet capture, dissection, and injection  | [scapy](https://pypi.org/project/scapy/) |

### 20.2 Standard Library Dependencies

| Module         | Used In                | Purpose                          |
|----------------|------------------------|----------------------------------|
| `datetime`     | `state_manager.py`, `arp_engine.py`, `logger.py` | Timestamps and time delta calculations |
| `collections`  | `state_manager.py`     | `defaultdict` for automatic key initialization |
| `os`           | `logger.py`, `env_check.py` | Directory creation and OS interaction |

### 20.3 System Dependencies

| Dependency           | Required | Purpose                                   |
|----------------------|----------|-------------------------------------------|
| Python 3.6+          | Yes      | Runtime interpreter                        |
| Linux Kernel 3.x+    | Yes      | Raw socket support via `AF_PACKET`         |
| libpcap / tcpdump    | Yes      | Backend for Scapy's packet capture engine  |
| Root/sudo access      | Yes      | Raw socket permissions                     |

---

## 21. Known Limitations

| ID    | Limitation                                          | Impact | Workaround |
|-------|-----------------------------------------------------|--------|------------|
| LIM-1 | **No state persistence** — All ARP baselines and state are lost on restart. | After restart, all previously observed IPs are treated as new, and the detection baseline must be relearned. | Implement serialization of `arp_table` to disk (e.g., JSON or SQLite). |
| LIM-2 | **Unbounded memory growth** — `arp_activity` lists accumulate timestamps indefinitely. | Long-running deployments on high-traffic networks may experience memory pressure. | Add periodic pruning of timestamps older than `FLOOD_WINDOW`. |
| LIM-3 | **Baseline MAC is immutable** — The initially observed MAC is never updated, even for legitimate changes. | Legitimate MAC changes (NIC replacement, VM migration) permanently trigger suspicious counts. | Implement a MAC update mechanism with a cooldown period. |
| LIM-4 | **Multi-IP alert repeats** — Once a MAC exceeds the 2-IP threshold, every subsequent ARP reply triggers a new alert. | Log flooding with duplicate alerts. | Add a "already alerted" flag per MAC. |
| LIM-5 | **No IPv6 support** — Only IPv4 ARP is monitored. | IPv6 NDP (Neighbor Discovery Protocol) spoofing is not detected. | Extend to monitor ICMPv6 NDP packets. |
| LIM-6 | **Single interface** — Only one NIC can be monitored per instance. | Multi-homed hosts require running multiple instances. | Add multi-interface support with threading. |
| LIM-7 | **No graceful shutdown** — Ctrl+C terminates without state summary or cleanup. | Operator receives no summary of observations at shutdown. | Add signal handlers for clean termination. |
| LIM-8 | **Relative log path** — Default `LOG_FILE` uses a relative path (`../logs/alerts.log`). | Log file location depends on the working directory at launch time. | Use absolute paths or `__file__`-relative paths. |
| LIM-9 | **No packet rate limiting on alerts** — Detection checks run on every ARP reply. | In high-traffic scenarios, the detection overhead adds to processing time. | Implement batched processing or sampling. |
| LIM-10 | **No configuration validation** — Invalid config values (e.g., negative thresholds) are not caught. | Runtime errors or silent misbehavior. | Add startup config validation. |

---

## 22. Future Enhancements Roadmap

| Priority | Enhancement                                      | Description |
|----------|--------------------------------------------------|-------------|
| P0       | **State Persistence**                             | Serialize `arp_table` to JSON/SQLite on shutdown and reload on startup to maintain baselines across restarts. |
| P0       | **Memory Management**                             | Implement timestamp pruning in `arp_activity` and alert deduplication for multi-IP detections. |
| P1       | **Graceful Shutdown**                             | Add `SIGINT`/`SIGTERM` handlers to print a summary and optionally save state. |
| P1       | **Configuration Validation**                      | Validate all config parameters at startup with clear error messages for invalid values. |
| P1       | **Startup Checks**                                | Verify root privileges, interface existence, and Scapy availability before entering the sniff loop. |
| P2       | **File-based Alert Logging with Rotation**        | Integrate Python's `logging` module with `RotatingFileHandler` for production-grade log management. |
| P2       | **External Alert Integration**                    | Add webhook, email, or Telegram notification support for real-time alerting. |
| P2       | **SIEM Integration**                              | Output alerts in CEF (Common Event Format) or JSON for ingestion by SIEM platforms (Splunk, ELK, etc.). |
| P3       | **GUI Dashboard**                                 | Web-based dashboard (Flask/FastAPI) showing real-time ARP table, alerts, and network topology. |
| P3       | **Multi-Interface Support**                       | Thread-per-interface model to monitor multiple NICs simultaneously. |
| P3       | **IPv6 NDP Monitoring**                           | Extend detection to cover IPv6 Neighbor Discovery Protocol spoofing attacks. |
| P3       | **Machine Learning Anomaly Detection**            | Train models on normal ARP traffic patterns to detect subtle, previously unknown attack vectors. |
| P3       | **Containerized Deployment**                      | Provide Docker image with `--net=host` for easy deployment on any Linux host. |
| P4       | **Unit Test Suite**                               | Activate and expand the commented-out unit tests. Add pytest framework and CI integration. |
| P4       | **Active Remediation**                            | Optionally send corrective ARP packets to restore poisoned caches (with appropriate safeguards). |

---

## Appendix A — Sample Output

### A.1 Normal Startup and Baseline Learning

```
[+] Listening on eth0
[BASELINE] 192.168.1.1 → AA:BB:CC:DD:EE:FF
[BASELINE] 192.168.1.100 → 00:11:22:33:44:55
[BASELINE] 192.168.1.200 → 66:77:88:99:AA:BB
```

### A.2 ARP Spoofing Detection

```
[+] Listening on eth0
[BASELINE] 192.168.1.1 → AA:BB:CC:DD:EE:FF
[2026-03-06 14:23:41] [ALERT] ARP Spoofing suspected! IP: 192.168.1.1, Old MAC: AA:BB:CC:DD:EE:FF, New MAC: 11:22:33:44:55:66
```

### A.3 Multi-IP Claiming Detection

```
[2026-03-06 14:24:10] [ALERT] MAC 11:22:33:44:55:66 claiming multiple IPs: ['192.168.1.1', '192.168.1.5', '192.168.1.10']
```

### A.4 ARP Flood Detection

```
[2026-03-06 14:25:00] [ALERT] ARP Flooding suspected from IP: 192.168.1.50
```

---

## Appendix B — Glossary of ARP Operations

| Opcode | Name            | Direction            | Description |
|--------|-----------------|----------------------|-------------|
| 1      | ARP Request     | Broadcast            | "Who has IP X? Tell IP Y." Sent when a host needs to resolve an IP to a MAC. |
| 2      | ARP Reply       | Unicast (typically)  | "IP X is at MAC Z." Sent in response to a request or unsolicited (gratuitous). |
| 3      | RARP Request    | Broadcast            | Reverse ARP — "Who has MAC Z? Tell me my IP." (Deprecated) |
| 4      | RARP Reply      | Unicast              | Reverse ARP reply. (Deprecated) |

**Note:** This tool monitors **opcode 2 (ARP Reply)** exclusively, as ARP spoofing attacks operate by sending forged reply packets.

---

## Appendix C — Revision History

| Version | Date       | Author      | Changes                          |
|---------|------------|-------------|----------------------------------|
| 1.0.0   | 2026-03-06 | Prashant B. | Initial release of TRD document. |

---

*End of Technical Reference Document*
