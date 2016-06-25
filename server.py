#!/usr/bin/env python
from scapy.all import *
import random
import binascii

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

serverPort = "9000"

class Server:
	def synAck(self,pkt):
		F = pkt['TCP'].flags
		if F & SYN:
			tcpSynAck = TCP(dport = 12345, sport = 80, flags = "SA", ack = 0,seq = 1 )
			send(IP(dst = "192.168.1.162")/tcpSynAck)

	def waitForConnection(self):
		sniff(iface="eth0", prn=self.synAck, store=0, filter = "tcp and port "+serverPort)


if __name__ == "__main__":
	try:
		server = Server()
		server.waitForConnection()
	except Exception as e:
		print e