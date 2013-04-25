#!/usr/bin/python -Btt

import sys
from scapy.all import *

def main(argv):
	for 1:
		recieved = sniff(filter="tcp and port 80", count=1) #prn=lambda x:x.sprintf("{TCP src: %TCP.sport%}"))
		print recieved[0]

if __name__ == '__main__':
	main(sys.argv)
