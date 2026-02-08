from scapy.all import sniff, ARP
from datetime import datetime

INTERFACE = "eth0"

def packet_handler(packet):
    # We only care about ARP packets for now
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        src_ip = arp_layer.psrc
        src_mac = arp_layer.hwsrc
        dst_ip = arp_layer.pdst
        dst_mac = arp_layer.hwdst

        print(f"[{timestamp}] ARP Packet")
        print(f"    Source IP : {src_ip}")
        print(f"    Source MAC: {src_mac}")
        print(f"    Target IP : {dst_ip}")
        print(f"    Target MAC: {dst_mac}")
        print("-" * 50)

print(f"[+] Starting packet sniffer on {INTERFACE}")
sniff(iface=INTERFACE, prn=packet_handler, store=False)





# sniff(
#   iface = eth0,
#   filter = "arp",
#   prn = callback_function,
#   store = False
# )

# iface → which ear you listen with
# filter → which sounds you care about
# prn → what you do when you hear something
# store → whether to save or discard