from scapy.all import sniff, ARP
from datetime import datetime
from defaultdict import defaultdic

INTERFACE = "eth0"

# This is our memory (state)
arp_table = {}

def packet_handler(packet):
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    # We only care about ARP replies for baselining
    if arp.op != 2:
        return

    timestamp = datetime.now()

    src_ip = arp.psrc
    src_mac = arp.hwsrc

    if src_ip not in arp_table:
        # First time seeing this IP
        arp_table[src_ip] = {
            "mac": src_mac,
            "first_seen": timestamp,
            "last_seen": timestamp
        }

        print(f"[BASELINE] {src_ip} is at {src_mac}")

    else:
        # IP already known
        known_mac = arp_table[src_ip]["mac"]

        if src_mac == known_mac:
            # Normal behavior
            arp_table[src_ip]["last_seen"] = timestamp
        else:
            # Change detected (do NOT alert yet)
            print("[CHANGE DETECTED]")
            print(f"    IP        : {src_ip}")
            print(f"    Old MAC   : {known_mac}")
            print(f"    New MAC   : {src_mac}")
            print("-" * 60)

            # Update last seen but keep old MAC for now
            arp_table[src_ip]["last_seen"] = timestamp

print(f"[+] Baseline engine started on {INTERFACE}")
sniff(iface=INTERFACE, prn=packet_handler, store=False)
