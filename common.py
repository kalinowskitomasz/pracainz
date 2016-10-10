#!/usr/bin/env python
from scapy.all import *
import random
from abc import ABCMeta, abstractmethod

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = "9000"

## iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <src_ip> -j DROP

def generate_data(n):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))


def enum(**enums):
	return type('Enum', (), enums)

States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)

#############################################################


def add_message_to_packet(tcp_pkt, message):
	(mask, message_encoded) = encode_message(message)
	tcp_pkt.urgptr = mask
	tcp_pkt.options = [(34, message_encoded)]
	return tcp_pkt

#############################################################


def decode_message(tcp_pkt):
	opts = __extract_options(tcp_pkt)
	message = __decode(opts, tcp_pkt.urgptr)
	return message

#############################################################


def encode_message(message):
	mask = random.randint(8, 255)
	message_buffer = ""
	#message_buffer += chr(mask)
	for c in message:
		char_int = ord(c)
		message_buffer += chr(char_int ^ mask)
		if len(message_buffer) == 38:
			return mask, message_buffer

	return mask, message_buffer

#############################################################


def __decode(message_byte, mask):
	message_buffer = ""

	if mask == 0 or mask is None:
		return None

	for c in message_byte:
		message_buffer += chr(ord(c) ^ mask)
	return message_buffer

#############################################################


def __extract_options(pkt):
	opts = pkt[TCP].options
	if len(opts) > 0:
		if len(opts[0]) == 2:
			if opts[0][0] == 34:
				return opts[0][1]
	return None

#############################################################



