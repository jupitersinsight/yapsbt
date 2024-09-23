from scapy.all import *

def ipconversations(pkt) -> str:
    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        conversation: str = "{0:<16}: {1:<5}  ==>  {2:<16}: {3:<5}  /  ".format(pkt[IP].src, pkt.sport, pkt[IP].dst, pkt.dport)
        if pkt.haslayer(Raw):
            conversation += "   {0}".format(pkt[Raw].load)
        return conversation
    
def ip6conversations(pkt) -> str:
    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        conversation: str = "{0:<16}: {1:<5}  ==>  {2:<16}: {3:<5}".format(pkt[IP].src, pkt.sport, pkt[IP].dst, pkt.dport)
        if pkt.haslayer(Raw):
            conversation += "   {0}".format(pkt[Raw].load)
        return conversation