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
	#msg = 'mrbaasman : P@s5w0Rt'
	clear = decrypt(key, 'qfwgw8gvnx2dzHO4d2H4Mzpw4istBIFvfn2dX/4S/QU=')
	print clear

	msg = ''
	while 1:
		recieved = sniff(filter="tcp and port 80", count=1)
		msg.append(chr(recieved[0].sport - 10000))
		print msg

if __name__ == '__main__':
	main(sys.argv)
