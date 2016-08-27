#!/usr/bin/env python
from scapy.all import *
import random

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = "9000"


def generate_data(n):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))


def enum(**enums):
	return type('Enum', (), enums)

