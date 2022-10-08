#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '10.9.0.5'
a.src = '10.1.1.1'
b = ICMP()
p = a/b

p.show()
send(p)
