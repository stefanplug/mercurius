#!/usr/bin/python -Btt

import sys
from scapy.all import *

def main(argv):
	recieved = sniff(filter="tcp and port 80", count=1, prn=lambda x:x.sprintf("{IP: From %IP.src%: %TCP.dport%}"))

if __name__ == '__main__':
	main(sys.argv)
