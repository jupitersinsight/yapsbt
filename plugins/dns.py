from scapy.all import *
from plugins.entropy import shannon_entropy
from time import sleep

# The Safelist contains FQDNs to be ignored, tweakable
safelist: list = ["connectivity-check.ubuntu.com.", "ubuntu.com", "local", "home", ""]

def dns_c2_beacon(pkt) -> str:
    """
    Live Traffic: True
    PCAP File: True
    """
    # Filters packets to pick only DNS over UDP or TCP
    if pkt.haslayer(DNS) and (pkt.haslayer(UDP) or pkt.haslayer(TCP)) and pkt.haslayer(IP):
        try:
            if pkt[DNS].qd.qname.decode() in safelist:
                return
        except:
            pass
        # Returns queries
        if pkt[DNS].qd and not pkt[DNS].an and str(pkt[DNS].qd.qname).split(".")[-2] not in safelist:
            # Translates QTYPES from integers to words
            qtype: str = ""
            match pkt[DNS].qd.qtype:
                case 1:
                    qtype: str = "A"
                case 2:
                    qtype: str = "NS"
                case 5:
                    qtype: str = "CNAME"
                case 6:
                    qtype: str = "SOA"
                case 12:
                    qtype: str = "PTR"
                case 15:
                    qtype: str = "MX"
                case 16:
                    qtype: str = "TXT"
                case 28:
                    qtype: str = "AAAA"
                case 65:
                    qtype: str = "HTTPS"
                case 255:
                    qtype: str = "*"
            subdomain: list = pkt[DNS].qd.qname.decode().split(".")
            subdomain.remove('')
            query_entropy: float = shannon_entropy(".".join(subdomain[:-2]).lower())
            sleep(1)
            return "IP: {0:<16} Type {1:<7} ID {2:<10} Query {3:<35} Subd entropy: {4}".format(pkt[IP].src, qtype, pkt[DNS].id, pkt[DNS].qd.qname.decode(), query_entropy)