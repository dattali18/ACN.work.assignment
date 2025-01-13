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


def write_attackers_to_file(detected_ips, output_file):
    """
    Write detected suspicious IPs to a file.

    :param detected_ips: Dictionary of detected IPs and their SYN packet counts
    :param output_file: Path to the output file
    """
    with open(output_file, "w") as f:
        for ip in detected_ips.keys():
            f.write(f"{ip}\n")


# Example Usage
syn_counter, syn_ack_counter = read_pcap("SYNflood.pcapng")
detected_ips = analyze_syn_flood(
    syn_counter,
    syn_ack_counter,
    syn_threshold=9,
    ratio_threshold=1.5,
    internal_ip_ranges=["100.64."],
)
write_attackers_to_file(detected_ips, "attackers_ip.txt")
