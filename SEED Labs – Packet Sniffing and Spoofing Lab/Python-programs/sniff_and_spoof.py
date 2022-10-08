#!/usr/bin/env python3
from scapy.all import *

print("Start sniffing packet....\n")

def sniff_and_spoof(pkt):
	if (pkt[ICMP].type == 8):
		print("Packet information:")
		print("Source: " + str(pkt[IP].src))
		print("Destination: " + str(pkt[IP].dst))
        
		new_ip = IP()
		new_ip.src = pkt[IP].dst
		new_ip.dst = pkt[IP].src
		
		new_icmp = ICMP()
		load = pkt[ICMP].load
		new_icmp.id = pkt[ICMP].id
		new_icmp.seq = pkt[ICMP].seq
		new_icmp.type = 0
		
		print("Spoofing packet...")
		
		reply = new_ip/new_icmp/load
		send(reply)
		print("\n")
	 
pkt = sniff(iface='br-91a1f05a03f3', filter='icmp', prn=sniff_and_spoof)
