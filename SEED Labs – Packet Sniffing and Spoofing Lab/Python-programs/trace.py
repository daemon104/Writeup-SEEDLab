#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '8.8.8.8'
i = 1

while 1:
	a.ttl = i
	b = ICMP()
	p = a/b
	resp = sr1(p)
	if resp is None:
		print('Can not reach destination host')
		break
	elif resp.type == 0:
		print('Traceroute done!! TTL: ' + str(i) + ' - IP: ' + str(resp.src)) 
		break
	else:
		print('TTL: ' + str(i) + ' - IP: ' + str(resp.src)) 
		
	i = i + 1
