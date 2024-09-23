from scapy.all import *

# Find NetBIOS Attack-in-the-Middle exploitation
def netbios_aitm(pkt) -> str:
    if pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        try:
            # Find NetBIOS requests
            if pkt.haslayer('NBNSQueryRequest'):
                netbios_data: dict = {
                    'type': 'request',
                    'src': pkt[IP].src,
                    'dst': pkt[IP].dst,
                    'trans_id': pkt.getlayer('NBNSHeader').NAME_TRN_ID,
                    'query': pkt.getlayer('NBNSQueryRequest').QUESTION_NAME.decode()
                }
                
                return f"{str(netbios_data['type']).upper()}-{netbios_data['trans_id']}: from {netbios_data['src']} to {netbios_data['dst']}. Query: where is {netbios_data['query']}"
            
            # Find NetBIOS responses
            elif pkt.haslayer('NBNSQueryResponse'):
                netbios_data: dict = {
                    'type': 'response',
                    'src': pkt[IP].src,
                    'dst': pkt[IP].dst,
                    'trans_id': pkt.getlayer('NBNSHeader').NAME_TRN_ID,
                    'answer': pkt.getlayer('NBNSQueryResponse').RR_NAME.decode(),
                    'ip': str(pkt.ADDR_ENTRY).split(" ")[7][11:]
                }
                trailing: str = "-"*105
                return f"{str(netbios_data['type']).upper()}-{netbios_data['trans_id']}: from {netbios_data['src']} to {netbios_data['dst']}. Answer: {netbios_data['answer']} is at {netbios_data['ip']}\n{trailing}"
            
        except:
            pass