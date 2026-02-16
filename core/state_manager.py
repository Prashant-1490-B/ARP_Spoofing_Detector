    # → Baseline & state memory
    from collections import defaultdict
    from datetime import datetime
    from collection import defaultdict

    class StateManager:
        def __init__(self):
            self.arp_table = {}
            self.mac_ip_map = defaultdict(set)
            self.arp_activity = defaultdict(list)

        def update_baseline(self, ip, mac):
            now = datetime.now()

            if ip not in self.arp_table:     #new ip, new dict
                self.arp_table[ip] = {
                    "mac": mac,
                    "first_seen": now,
                    "last_seen": now,
                    "suspicious_count": 0
                }
                return "NEW"

            return "EXISTS"

        def record_activity(self, ip):
            now = datetime.now()
            self.arp_activity[ip].append(now)
            return now
