from scapy.all import *

# The Safelist contains FQDNs to be ignored, tweakable
safelist: list = ["connectivity-check.ubuntu.com.", "ubuntu.com", "local", "home", ""]

def dns_qr(pkt) -> str:
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
            return "{0:<16} send a query for type {1:<7} transaction ID {2:<10} for hostname/ip {3:<100}".format(pkt[IP].src, qtype, pkt[DNS].id, pkt[DNS].qd.qname.decode())
        
        # Returns answers
        if pkt[DNS].qd and pkt[DNS].an:
            # Translates TYPES from integers to words
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
            #return f'{pkt[IP].src} answer is {pkt[DNS].an.rdata} to request with ID {pkt[DNS].id}'
            return "{0:<16} send an answer for type {1:<5} transaction ID {2:<10} with value {3:<100}".format(pkt[IP].src, qtype, pkt[DNS].id, pkt[DNS].qd.qname.decode())