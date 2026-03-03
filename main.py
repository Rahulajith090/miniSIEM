from log_parser import FirewallParser
from analyzer import LogAnalyzer

# Parse logs
parser = FirewallParser("sample_logs.txt")
logs = parser.parse_file()

if not logs:
    print("No valid logs parsed.")
    exit()

# Analyze logs
analyzer = LogAnalyzer(logs)

print("\n===== BASIC ANALYSIS REPORT =====")

# 🔹 Top Attackers
print("\nTop Attackers:")
top_attackers = analyzer.get_top_attackers()
if top_attackers:
    for ip, count in top_attackers:
        print(f"{ip} → {count} attempts")
else:
    print("No blocked attacks found.")

# 🔹 Top Ports
print("\nTop Targeted Ports:")
top_ports = analyzer.get_top_ports()
if top_ports:
    for port, count in top_ports:
        print(f"Port {port} → {count} attempts")
else:
    print("No blocked ports found.")

# 🔹 Protocol Stats
print("\nProtocol Distribution:")
protocol_stats = analyzer.get_protocol_stats()
if protocol_stats:
    for proto, count in protocol_stats.items():
        print(f"{proto} → {count}")
else:
    print("No protocol data available.")

# 🔹 Action Stats
print("\nAction Distribution:")
action_stats = analyzer.get_action_stats()
if action_stats:
    for action, count in action_stats.items():
        print(f"{action} → {count}")
else:
    print("No action data available.")

# 🔹 Unique Attackers
print("\nUnique Attackers:", analyzer.get_unique_attackers())

print("\n===== ATTACK CLASSIFICATION =====")

attack_results = analyzer.classify_attacks()

if attack_results:
    for ip, details in attack_results.items():
        print(f"\nIP: {ip}")
        print("Attack Type:", details["attack_type"])
        print("Total Attempts:", details["total_attempts"])
        print("Unique Ports:", details["unique_ports"])
else:
    print("No classified attacks found.")