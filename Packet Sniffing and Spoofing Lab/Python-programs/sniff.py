#!/usr/bin/env python3
from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='br-91a1f05a03f3', filter='tcp and dst port 23', prn=print_pkt)


