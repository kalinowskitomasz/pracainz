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


def generate_data():
	return "abcd"
