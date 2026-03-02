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
        protocols = [log["protocol"] for log in self.logs]
        return Counter(protocols)

    # 🔹 Count Blocked vs Allowed
    def get_action_stats(self):
        actions = [log["action"] for log in self.logs]
        return Counter(actions)

    # 🔹 Unique Attackers
    def get_unique_attackers(self):
        ips = {log["src_ip"] for log in self.logs if log.get("action") == "BLOCK"}
        return len(ips)