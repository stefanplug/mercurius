#!/usr/bin/python -Btt

import sys
from scapy.all import *

def create_frame(test, test2):
	frame = Ether()
	return frame

def create_packet():
	packet = IP()
	#packet.version = 4
	#packet.tos = 
	#packet.len =
	#packet.id =
	#packet.flags =
	#packet.frag =
	#packet.ttl =
	#packet.proto =
	#packet.chksum =
	packet.src = '192.168.10.100'
	packet.dst = '192.168.10.2'
	#packet.options =
	return packet

def create_segment():
	segment = TCP()
	return segment

def main(argv):
	packet = create_packet()
	send(packet)

if __name__ == '__main__':
	main(sys.argv)
