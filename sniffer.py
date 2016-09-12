#!/usr/bin/env python

from scapy.all import *


if __name__ == "__main__":
	sniff(filter="tcp port 50000", prn=lambda x: x.summary())
