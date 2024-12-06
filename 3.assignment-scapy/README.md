# ACN - Advanced Computer Networks

- Daniel Attali - 328780879

## Assignment 3 - Scapy

**overview**

In this assignment, we are tasked to write a `dnsmap` like script using `scapy` to perform a DNS enumeration attack on a domain. The script should be able to perform the following tasks:

---

### DNS Enumeration Assignment *Requirements*

#### **Objective**

Develop a Python script for DNS enumeration using **Scapy** and related tools to analyze and extract domain information. The purpose is to demonstrate understanding and proficiency in DNS analysis and scripting.

#### **Requirements**
1. **Domain Discovery**:
   - Identify the authoritative DNS server for a given domain.
   - Perform `SOA` (Start of Authority) queries using Scapy to gather administrative information about the domain.
   - Output the authoritative DNS server's name and its IPv4 addresses.

2. **Tool Experimentation**:

   - Use the **dnsmap** tool to map subdomains of the target domain.
   - Install and run dnsmap on a Linux system (e.g., WSL or a Linux VM).
   - Perform network sniffing with Wireshark while running dnsmap and analyze how the target server determines whether the queried domain exists.

3. **Custom Wordlist**:

   - Download the `dnsmap.h` and `wordlist_TLAs.txt` files from the dnsmap GitHub repository.
   - Extract words from the provided files or create your custom wordlist for subdomain enumeration.

4. **Python Script for DNS Mapping**:

   - Develop a Python script named `enumdns.py` that:
     - Takes a domain name as an argument (not through standard input).
     - Reads subdomain candidates from a custom wordlist.
     - Queries each subdomain and retrieves:
       - Available DNS servers.
       - Their corresponding IPv4 addresses.
   - Print the results for each subdomain in a structured format.

#### **Additional Notes**:
- Use only IPv4 for all queries (IPv6 support is optional but not required).
- Experiment with different DNS servers and observe variations in responses.
- Include comments and structured output in the script for clarity.

#### **Example Output**:
For a query on `jct.ac.il`:
- **Authoritative DNS Server**: `dns.jct.ac.il`
- **SOA Details**:
  - Primary Name Server: `ns.jct.ac.il`
  - Admin Email: `admin@jct.ac.il`
- **Subdomain Mapping**:
  - Subdomain: `mail.jct.ac.il`
    - IPv4: `192.115.123.1, 192.115.123.2`