def compare_ip_lists(detected_file, attackers_file):
    """
    Compare two files containing IP addresses and print discrepancies.

    :param detected_file: Path to the file with detected suspicious IPs
    :param attackers_file: Path to the file with the actual attackers
    """
    # Read the detected IPs into a set
    with open(detected_file, "r") as f:
        detected_ips = {line.strip() for line in f if line.strip()}

    # Read the actual attacker IPs into a set
    with open(attackers_file, "r") as f:
        attacker_ips = {line.strip() for line in f if line.strip()}

    # Perform set operations
    correctly_detected = detected_ips.intersection(attacker_ips)
    missed_attackers = attacker_ips.difference(detected_ips)
    false_positives = detected_ips.difference(attacker_ips)

    # Print results
    print(f"Total attackers given: {len(attacker_ips)}")
    print(f"Total detected IPs: {len(detected_ips)}")
    print(f"Correctly detected attackers: {len(correctly_detected)}")
    print(f"Missed attackers: {len(missed_attackers)}")
    print(f"False positives: {len(false_positives)}\n")

    print("Missed Attackers:")
    for ip in missed_attackers:
        print(ip)

    print("\nFalse Positives:")
    for ip in false_positives:
        print(ip)


# Usage
compare_ip_lists("suspicious_ips1.txt", "attackersListFiltered.txt")
