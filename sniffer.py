#!/usr/bin/env python3

# Import
from scapy.all import *
import plugins as ps
import sys
import datetime

# Sniff live traffic
def sniffLive(interface, bpf=None, action=None):
    # List of packets that can be write to a pcap file
    packets: list = []
    # If no action is specified default one is applied to each packet
    if action == None or action == '':
        sniff(iface=interface, filter=bpf, prn=lambda p: (p.summary(), packets.append(p))[0])
    # Otherwise apply the specified action to each packet
    else:
        sniff(iface=interface, filter=bpf, prn=lambda p: (getattr(ps, action)(p), packets.append(p))[0])
    # Once the execution of the sniffer is aborted, captured packet files can be written to a pcap file.
    # By default caputered packets are not saved.
    # pcap filename will always include current date DAY-MONTH-YEAR prefixed by an optional string of choice
    choice: str = input("\nWould you like to save the capture to a PCAP file? y/N\n").lower()
    if choice == "y" or choice == "yes":
        filename: str = input("\nAdd a distinctive filename to the PCAP file. Skip if not needed.\n").lower()
        if filename != "":
            filename: str = filename + "_"
        wrpcap(f"{filename}{datetime.date.today().strftime('%d-%b-%Y')}.pcap", packets)
    else:
        sys.exit(0)

# Sniff from a PCAP file
def sniffOffline(pcap, bpf=None, action=None):
    # If no action is specified default one is applied to each packet
    if action == None or action == '':
        sniff(offline=pcap, filter=bpf, prn=lambda p: (p.summary()))
    # Otherwise apply the specified action to each packet
    else:
        sniff(offline=pcap, filter=bpf, prn=lambda p: (getattr(ps, action)(p)))

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Sniff live traffic or read pcap files", epilog="by Andrea _flatline_ Calarco")
    parser.add_argument("-r", "--read", help="Pcap file(s) from which to read packets from", required=False, default=[], nargs="*")
    parser.add_argument("-b", "--bpf", help="BPF to limit the packets to parse", required=False, default='')
    parser.add_argument("-i", "--interface", help="Interface to read live packets from", required=False, default=None)
    parser.add_argument("-a", "--action", help="Specify which module to load", required=False, default='')
    
    # parse_known_args returns a tuple of 'known' and 'unknown' arguments. Unlike parse.args, no error is returned if extra arguments are given
    (known_args, unknown_args) = parser.parse_known_args()
    parsed_args: dict = vars(known_args)
    
    # If no source is specified, a warning is printed on screen
    if parsed_args["interface"] == None and parsed_args["read"] == []:
        print("Missing source")
        sys.exit(1)
        
    try:
        # If the source interface is specified starts sniffing live traffic
        if parsed_args['interface']:
            if_name: str = parsed_args["interface"]
            sniffLive(interface=parsed_args["interface"], bpf=parsed_args["bpf"], action=parsed_args["action"])
            sys.exit(0)
        # If one or more pcap files are specified starts sniffing those files
        if parsed_args['read']:
            for source in parsed_args["read"]:
                sniffOffline(source, bpf=parsed_args["bpf"], action=parsed_args["action"])
            sys.exit(0)
        # If no source if specified prints error and exit
        else:
            print("Something unexpected occurred")
            sys.exit(1)
            
    except KeyboardInterrupt:
        pass
        