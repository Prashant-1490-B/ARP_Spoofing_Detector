from scapy.all import sniff, ARP
import os

print("[+] Enviornment Check")

def packet_callback(pkt):
    if pkt.haslayer(ARP):
        print("[+] Packet Captured")
        sniff(count=1)

sniff(prn=packet_callback,count=1)

