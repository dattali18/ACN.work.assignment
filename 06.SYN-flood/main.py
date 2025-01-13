from scapy.all import rdpcap, TCP
from collections import Counter, defaultdict


def analyze_syn_flood(pcap_file, internal_ip_ranges=None):
    """
    Analyze a pcapng file for SYN flood attack patterns.

    :param pcap_file: Path to the pcapng file
    :param internal_ip_ranges: List of internal/private IP ranges to whitelist (optional)
    :return: Detected SYN packet counts and flagged IPs
    """
    packets = rdpcap(pcap_file)
    syn_counter = Counter()
    syn_ack_counter = defaultdict(set)

    # Parse packets
    for pkt in packets:
        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
            ip_layer = pkt["IP"]
            tcp_layer = pkt["TCP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if tcp_layer.flags == 0x02:  # SYN flag
                syn_counter[src_ip] += 1
            elif tcp_layer.flags == 0x12:  # SYN-ACK flag
                syn_ack_counter[dst_ip].add(src_ip)

    # Filter suspicious IPs based on SYN packets without SYN-ACK responses
    suspicious_ips = {
        ip: count for ip, count in syn_counter.items() if ip not in syn_ack_counter
    }

    # Optionally remove internal/private IPs
    if internal_ip_ranges:
        suspicious_ips = {
            ip: count
            for ip, count in suspicious_ips.items()
            if not any(ip.startswith(prefix) for prefix in internal_ip_ranges)
        }

    # Output results
    print("=== SYN Flood Analysis Results ===")
    print(f"Total SYN packets analyzed: {sum(syn_counter.values())}")
    print(f"Total unique IPs: {len(syn_counter)}")
    print(f"Suspicious IPs: {len(suspicious_ips)}\n")

    print("Suspicious IPs and SYN packet counts:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} SYN packets")

    return syn_counter, suspicious_ips


def compare_results(detected_ips, attackers_file):
    """
    Compare detected suspicious IPs against the given list of attackers.

    :param detected_ips: Dictionary of detected IPs and their SYN packet counts
    :param attackers_file: Path to the file with the actual attackers
    """
    with open(attackers_file, "r") as f:
        attacker_ips = {line.strip() for line in f if line.strip()}

    detected_set = set(detected_ips.keys())
    correctly_detected = detected_set.intersection(attacker_ips)
    missed_attackers = attacker_ips.difference(detected_set)
    false_positives = detected_set.difference(attacker_ips)

    print("\n=== Comparison Results ===")
    print(f"Total attackers given: {len(attacker_ips)}")
    print(f"Total detected IPs: {len(detected_set)}")
    print(f"Correctly detected attackers: {len(correctly_detected)}")
    print(f"Missed attackers: {len(missed_attackers)}")
    print(f"False positives: {len(false_positives)}\n")

    print("Missed Attackers:")
    for ip in missed_attackers:
        print(ip)

    print("\nFalse Positives:")
    for ip in false_positives:
        print(ip)


# Example Usage
# Step 1: Analyze the pcap file for SYN flood patterns
syn_counts, detected_ips = analyze_syn_flood(
    "SYNflood.pcapng", internal_ip_ranges=["100.64."]
)

# Step 2: Compare results with the provided attackers list
compare_results(detected_ips, "attackersListFiltered.txt")
