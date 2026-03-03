from collections import Counter

class LogAnalyzer:
    def __init__(self, parsed_logs):
        self.logs = parsed_logs

    # 🔹 Top Attacking IPs
    def get_top_attackers(self, limit=5):
        ips = [log["src_ip"] for log in self.logs if log.get("action") == "BLOCK"]
        return Counter(ips).most_common(limit)

    # 🔹 Most Targeted Ports
    def get_top_ports(self, limit=5):
        ports = [log["port"] for log in self.logs if log.get("action") == "BLOCK"]
        return Counter(ports).most_common(limit)

    # 🔹 Protocol Distribution
    def get_protocol_stats(self):
        protocols = [log["protocol"] for log in self.logs if "protocol" in log]
        return Counter(protocols)

    # 🔹 Count Blocked vs Allowed
    def get_action_stats(self):
        actions = [log["action"] for log in self.logs if "action" in log]
        return Counter(actions)

    # 🔹 Unique Attackers
    def get_unique_attackers(self):
        ips = {log["src_ip"] for log in self.logs if log.get("action") == "BLOCK"}
        return len(ips)

    # 🔥 FIXED: Properly indented inside class
    def classify_attacks(self):
        attack_summary = {}

        for log in self.logs:
            if log.get("action") != "BLOCK":
                continue

            ip = log["src_ip"]
            port = log["port"]

            if ip not in attack_summary:
                attack_summary[ip] = {
                    "ports": set(),
                    "total_attempts": 0,
                    "ssh_attempts": 0,
                    "web_attempts": 0
                }

            attack_summary[ip]["ports"].add(port)
            attack_summary[ip]["total_attempts"] += 1

            if port == 22:
                attack_summary[ip]["ssh_attempts"] += 1

            if port in [80, 443]:
                attack_summary[ip]["web_attempts"] += 1

        # 🔹 Classification Phase
        results = {}

        for ip, data in attack_summary.items():
            unique_ports = len(data["ports"])
            total = data["total_attempts"]

            if unique_ports > 5:
                attack_type = "Port Scanning"
            elif data["ssh_attempts"] > 5:
                attack_type = "SSH Brute Force"
            elif data["web_attempts"] > 10:
                attack_type = "Web Attack"
            else:
                attack_type = "Suspicious Activity"

            results[ip] = {
                "attack_type": attack_type,
                "total_attempts": total,
                "unique_ports": unique_ports
            }

        return results