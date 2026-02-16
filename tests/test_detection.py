# → Basic detection tests
from core.state_manager import StateManager
from core.arp_engine import ARPEngine

def test_baseline():
    state = StateManager()
    engine = ARPEngine(state, "logs/test.log")

    engine.process_reply("192.168.1.1", "AA:BB:CC:DD:EE:FF")
    assert "192.168.1.1" in state.arp_table
