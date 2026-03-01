from datetime import timedelta
from config import ALERT_THRESHOLD, FLOOD_WINDOW, FLOOD_LIMIT
from utils.logger import log_alert

class ARPEngine:
    def __init__(self, state_manager, log_file):
        self.state = state_manager
        self.log_file = log_file

    def process_reply(self, ip, mac):
        status = self.state.update_baseline(ip, mac)

        if status == "NEW":
            print(f"[BASELINE] {ip} → {mac}")
            return

        known_mac = self.state.arp_table[ip]["mac"]

        # MAC change detection
        if mac != known_mac:
            self.state.arp_table[ip]["suspicious_count"] += 1

            if self.state.arp_table[ip]["suspicious_count"] >= ALERT_THRESHOLD:
                log_alert(
                    f"[ALERT] ARP Spoofing suspected! IP: {ip}, "
                    f"Old MAC: {known_mac}, New MAC: {mac}",
                    self.log_file
                )
        else:
            self.state.arp_table[ip]["suspicious_count"] = 0

        # Multi-IP detection
        self.state.mac_ip_map[mac].add(ip)
        if len(self.state.mac_ip_map[mac]) > 2:
            log_alert(
                f"[ALERT] MAC {mac} claiming multiple IPs: "
                f"{list(self.state.mac_ip_map[mac])}",
                self.log_file
            )

        # Flood detection
        now = self.state.record_activity(ip)
        recent = [
            t for t in self.state.arp_activity[ip]
            if now - t < timedelta(seconds=FLOOD_WINDOW)
        ]

        if len(recent) >= FLOOD_LIMIT:
            log_alert(
                f"[ALERT] ARP Flooding suspected from IP: {ip}",
                self.log_file
            )
