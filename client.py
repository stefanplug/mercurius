#!/usr/bin/python -Btt

import sys
from scapy.all import *

def create_frame(test, test2):
	frame = Ether()
	#frame.dst =
	#frame.src =
	#frame.type =
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
	segment.sport = 10000
	segment.dport = 80
	#segment.seq =
	#segment.ack =
	#segment.dataofs =
	#segment.reserved =
	segment.flags = 0x02
	#segment.window =
	#segment.chksum =
	#segment.urgptr =
	#segment.options =
	return segment

def create_datagram():
	datagram = UDP()
	#datagram.sport =
	#datagram.dport =
	#datagram.len =
	#datagram.chksum =
	return datagram

def main(argv):
	packet = create_packet()
	segment = create_segment()
	send(packet/segment)

if __name__ == '__main__':
	main(sys.argv)
