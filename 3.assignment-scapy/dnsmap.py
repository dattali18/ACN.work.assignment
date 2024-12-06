# dns map script using scapy
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1
from scapy.all import *

import re

from typing import List, Tuple


# The list of possible subdomains are stored in a file called subdomains.txt
def get_subdomains() -> List[str]:
    subdomains = []
    with open("subdomains.txt") as file:
        for line in file:
            subdomains.append(line.strip())
    return subdomains


def validate_domain(domain: str) -> bool:
    # this function will take as input the args given by the user
    # and will check if the domain is valid
    # e.g. valid: google.com, www.google.com
    # invalid: google, google.com.

    # using regex to validate the domain
    pattern = re.compile(r"^(www\.)?([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$")
    return pattern.match(domain) is not None


def query_subdomain(domain: str, subdomain: str) -> Tuple[str, List[str]]:
    """Perform a DNS query for a subdomain."""
    fqdn = f"{subdomain}.{domain}"
    query = sr1(
        IP(dst="8.8.8.8") / UDP(sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=fqdn)),
        verbose=0,
        timeout=2,
    )

    if query and query.haslayer(DNS) and query[DNS].an:
        # Extract answers from the DNS response
        ips = []
        for i in range(query[DNS].ancount):
            answer = query[DNS].an[i]
            if hasattr(answer, "rdata"):
                ips.append(answer.rdata)
        return fqdn, ips

    # No valid answer
    return fqdn, None


# def main(args: List[str]) -> None:
#     print("DNS Mapping for domain: ", args[1])

#     domain = args[1]

#     if not validate_domain(domain):
#         print("Invalid domain")
#         sys.exit(1)

#     subdomains = get_subdomains()

#     results = []

#     for subdomain in subdomains:
#         fqdn, ips = query_subdomain(domain, subdomain)
#         if ips:
#             results.append((fqdn, ips))

#     # print the results
#     for fqdn, ips in results:
#         print(fqdn, "=>", ips)


def main(args: List[str]) -> None:
    print("DNS Mapping for domain:", args[1])

    domain = args[1]

    if not validate_domain(domain):
        print("Invalid domain")
        sys.exit(1)

    subdomains = get_subdomains()

    results = []

    for subdomain in subdomains:
        fqdn, ips = query_subdomain(domain, subdomain)
        if ips:
            results.append((fqdn, ips))

    # Print the results
    print("\nMapping Results:\n")
    for fqdn, ips in results:
        print(f"Subdomain: {fqdn}")
        print(f"  IPs/References:")
        for ip in ips:
            # Decode byte strings if necessary
            ip = ip.decode() if isinstance(ip, bytes) else ip
            print(f"    - {ip}")
        print()  # Add a blank line for better readability


if __name__ == "__main__":
    # get the command line arguments
    import sys

    args = sys.argv
    # check the number of arguments
    if len(args) != 2:
        print("Usage: python dnsmap.py <domain>")
        sys.exit(1)

    main(args)
