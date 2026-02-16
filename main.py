# → Entry point (CLI + orchestration)
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
