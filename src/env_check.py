from scapy.all import sniff
import os

def packet_callback(pkt):
    if pkt.haslayer(ARP):
        print("[+] Packet Captured")
        sniff(count=1)

sniff(prn=packet_callback,count=1)

