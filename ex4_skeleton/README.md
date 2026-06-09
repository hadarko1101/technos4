# Exercise 4 Bonus - Hadar Koren & Itay Schechner

In this exercise we've implemented the `ArpSpoofDetector` class to detect and trace ARP Spoofing attacks in the local network. 

1. How the Detection Works
    The detector passively sniffs the network for ARP packets (`ARP_FILTER = "arp"`). It maintains a dictionary (`ip_to_mac`) that maps IP addresses to their last known MAC address. 
    If an ARP packet is received and its MAC address contradicts the previously recorded MAC address for that IP, a suspicious ARP change is flagged.

2. Identifying the Attacker's True IP
    Once a spoofed packet is detected, the detector attempts to find the attacker's real IP address. It does this by actively broadcasting an ARP request to the entire subnet (`NETWORK_SCAN_CIDR`, which is 10.0.2.0/24 in our case). It then filters the responses to see which other IPs on the network share the **same MAC address** as the suspicious packet. The matching IP address is highly likely to be the attacker's true IP.

3. Response Mechanisms
    If an attack is detected, several steps can be taken to handle it:
    a. **Static ARP Tables:** For critical infrastructure (like the Default Gateway or DNS Server), we can configure static ARP entries on the host machine so they cannot be dynamically updated or poisoned. We can then repeatedly broadcast legitimate ARP responses to the network that will "correct" poisoned ARP caches (Gratuitous ARP).
    b. **Network-Level Blocking:** Alert the network switch or firewall to drop traffic originating from the malicious MAC address.

4. Design Considerations & Edge Cases
    a. IP or MAC Changes
    If a legitimate computer simply changes its network interface (e.g., switching from Wi-Fi to Ethernet, or getting a new NIC), its MAC address will change while keeping the same IP, or vice versa. The detector will flag this as a false positive. 
    b. Should we protect every IP?
    Protecting *every* IP address on the network might be computationally expensive and prone to false positives in dynamic DHCP environments. The most critical targets to protect and monitor are the **Default Gateway**, **DNS Servers**, as these are the key ways to construct an attack.
    c. Frequency of Variables:
        - **MAC Addresses:** Rarely change for a specific device.
        - **IP Addresses:** Change frequently depending on the DHCP lease time. Because IP addresses rotate, binding them strictly to a MAC address forever will inevitably cause false positives when a lease expires and is handed to a new device.
    d. False-Positives vs False-Negatives
        - **Cost of False-Positive:** An incorrect identification of an attack could lead to a legitimate user being blocked from the network. 
        - **Cost of False-Negative:** Missing a real attack allows attacks to happen, which is way worse than the cost of a false positive.
