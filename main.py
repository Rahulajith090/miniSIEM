from log_parser import FirewallParser
from analyzer import LogAnalyzer

# Parse logs
parser = FirewallParser("sample_logs.txt")
logs = parser.parse_file()

# Analyze logs
analyzer = LogAnalyzer(logs)

print("\n===== BASIC ANALYSIS REPORT =====")

print("\nTop Attackers:")
for ip, count in analyzer.get_top_attackers():
    print(f"{ip} → {count} attempts")

print("\nTop Targeted Ports:")
for port, count in analyzer.get_top_ports():
    print(f"Port {port} → {count} attempts")

print("\nProtocol Distribution:")
print(analyzer.get_protocol_stats())

print("\nAction Distribution:")
print(analyzer.get_action_stats())

print("\nUnique Attackers:", analyzer.get_unique_attackers())