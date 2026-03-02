import re
from datetime import datetime

class FirewallParser:
    def __init__(self, filename):
        self.filename = filename
        self.parsed_logs = []
        self.failed_lines = 0

    def parse_line(self, line):
        data = {}

        # Timestamp (Jan 24 10:15:30)
        timestamp_match = re.search(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
        if timestamp_match:
            data["timestamp"] = timestamp_match.group(1)

        # Action (BLOCK or ALLOW)
        action_match = re.search(r"\[UFW (\w+)\]", line)
        if action_match:
            data["action"] = action_match.group(1)

        # Source IP
        src_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
        if src_match:
            data["src_ip"] = src_match.group(1)

        # Destination IP
        dst_match = re.search(r"DST=(\d+\.\d+\.\d+\.\d+)", line)
        if dst_match:
            data["dst_ip"] = dst_match.group(1)

        # Protocol
        proto_match = re.search(r"PROTO=(\w+)", line)
        if proto_match:
            data["protocol"] = proto_match.group(1)

        # Destination Port
        dpt_match = re.search(r"DPT=(\d+)", line)
        if dpt_match:
            data["port"] = int(dpt_match.group(1))

        # If essential fields missing → invalid
        if "src_ip" not in data or "port" not in data:
            return None

        return data

    def parse_file(self):
        with open(self.filename, "r") as file:
            for line in file:
                parsed = self.parse_line(line.strip())
                if parsed:
                    self.parsed_logs.append(parsed)
                else:
                    self.failed_lines += 1

        return self.parsed_logs