from scapy.all import rdpcap, TCP
from collections import Counter, defaultdict


def read_pcap(pcap_file):
    """
    Read a pcapng file and extract SYN and SYN-ACK packet counts.

    :param pcap_file: Path to the pcapng file
    :return: SYN packet counts, SYN-ACK packet counts
    """
    packets = rdpcap(pcap_file)
    syn_counter = Counter()
    syn_ack_counter = Counter()

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
                syn_ack_counter[dst_ip] += 1

    return syn_counter, syn_ack_counter


def analyze_syn_flood(
    syn_counter,
    syn_ack_counter,
    syn_threshold=9,
    ratio_threshold=1.5,
    internal_ip_ranges=None,
):
    """
    Analyze SYN and SYN-ACK packet counts for SYN flood attack patterns.

    :param syn_counter: SYN packet counts
    :param syn_ack_counter: SYN-ACK packet counts
    :param syn_threshold: Minimum SYN packets to flag an IP as suspicious
    :param ratio_threshold: Minimum ratio of SYN to SYN-ACK packets to flag an IP as suspicious
    :param internal_ip_ranges: List of internal/private IP ranges to whitelist (optional)
    :return: Detected SYN packet counts and flagged IPs
    """
    # Filter suspicious IPs based on SYN packets and SYN/SYN-ACK ratio
    suspicious_ips = {
        ip: count
        for ip, count in syn_counter.items()
        if count > syn_threshold
        and (count / (syn_ack_counter[ip] + 1)) > ratio_threshold
    }

    # Optionally remove internal/private IPs
    if internal_ip_ranges:
        suspicious_ips = {
            ip: count
            for ip, count in suspicious_ips.items()
            if not any(ip.startswith(prefix) for prefix in internal_ip_ranges)
        }

    return suspicious_ips


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

    return len(false_positives), len(missed_attackers), len(correctly_detected)


# Example Usage
syn_counter, syn_ack_counter = read_pcap("SYNflood.pcapng")
detected_ips = analyze_syn_flood(
    syn_counter,
    syn_ack_counter,
    syn_threshold=9,
    ratio_threshold=1.5,
    internal_ip_ranges=["100.64."],
)
false_positives, missed_attackers, correctly_detected = compare_results(
    detected_ips, "attackersListFiltered.txt"
)

print(f"False Positives: {false_positives}, Missed Attackers: {missed_attackers}")
print(f"Correctly Detected Attackers: {correctly_detected}")
