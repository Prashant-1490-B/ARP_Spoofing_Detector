from scapy.all import ARP, Ether, sendp

pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2,
    psrc="192.168.1.1",
    hwsrc="aa:bb:cc:dd:ee:ff",
    pdst="192.168.1.200"
)

sendp(pkt, iface="eth0", verbose=False)


# → Basic detection tests
# from core.state_manager import StateManager
# from core.arp_engine import ARPEngine

# def test_baseline():
#     state = StateManager()
#     engine = ARPEngine(state, "logs/test.log")

#     engine.process_reply("192.168.1.1", "AA:BB:CC:DD:EE:FF")
#     assert "192.168.1.1" in state.arp_table

# def test_mac_change():
#     state = StateManager()
#     engine = ARPEngine(state, "logs/test.log")

#     engine.process_reply("192.168.1.1", "AA:BB")
#     engine.process_reply("192.168.1.1", "CC:DD")
#     engine.process_reply("192.168.1.1", "AA")
#     engine.process_reply("192.168.1.2", "AA")
#     engine.process_reply("192.168.1.3", "AA")

#     assert state.arp_table["192.168.1.1"]["suspicious_count"] == 2

    
