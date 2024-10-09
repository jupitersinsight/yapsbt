from scapy.all import *

def ftp_commands(pkt) -> str:
    """
    Live traffic: True
    PCAP file: True
    """
    if pkt.haslayer(TCP):
            if (pkt.sport == 21 or pkt.dport == 21) and pkt.haslayer(Raw):
                command: dict = {
                    'src': pkt[IP].src,
                    'src port': pkt[TCP].sport,
                    'dst': pkt[IP].dst,
                    'dst port': pkt[TCP].dport,
                    'ftp payload': pkt[Raw].load.decode().strip().replace("\r\n", " ")
                    }
                
                if command['ftp payload'][:4].strip() == "227":
                    pasv_request: str = command['ftp payload']
                    broken_command: list = pasv_request.split(" ")[-1].replace("(", "").replace(")", "").replace(".", "").split(",")
                    ip: str = ".".join(broken_command[0:4])
                    port: str = (int(broken_command[4])*256)+(int(broken_command[-1]))
                    command['ftp payload'] = command['ftp payload'] + f" | FTP-DATA channel open at {ip}:{port}"
                    
                    
                return f"{command['src']:<16}: {command['src port']:<5}   ==>    {command['dst']:<16}:{command['dst port']:<5}  /  {command['ftp payload']}"
    