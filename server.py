#!/usr/bin/python -Btt

import sys
from scapy.all import *

def main(argv):
	while 1:
		recieved = sniff(filter="tcp and port 80", count=1)
		print recieved[0].sport

if __name__ == '__main__':
	main(sys.argv)
