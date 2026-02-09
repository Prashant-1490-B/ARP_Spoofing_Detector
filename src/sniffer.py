from scapy.all import sniff, ARP
from datetime import datetime

INTERFACE = "eth0"

def packet_handler(packet):
    # We only care about ARP packets for now
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    src_ip = arp.psrc
    src_mac = arp.hwsrc
    dst_ip = arp.pdst
    dst_mac = arp.hwdst

# ARP Operation Type:
     
    if arp.op == 1:
            arp_type = "REQUEST"
            message = f"Who has {dst_ip}? Tell {src_ip}"
    elif arp.op == 2:
            arp_type = "REPLY"
            message = f"{src_ip} is at {src_mac}"
    else:
            arp_type = "UNKNOWN"
            message = "Unknown ARP operation"


    print(f"[{timestamp}] ARP Packet {arp_type}")
    print(f"    {message}")
    print(f"    Target MAC : {dst_mac}")
    print(f"    Target MAC: {dst_mac}")
    print("-" * 50)

print(f"[+] Listening on {INTERFACE}(ARP only)")
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