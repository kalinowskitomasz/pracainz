#!/usr/bin/env python
from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = "9000"


class Server:
	def __init__(self):
		self.destination_port = 12345
		self.seq = 0
		self.ack = 0
		self.is_connected = False

	def send_syn_ack(self, pkt):
		flag = pkt['TCP'].flags
		if flag & SYN:
			tcp_syn_ack = TCP(dport=self.destination_port, sport=80, flags="SA", ack=0, seq=1)
			send(IP(dst="192.168.1.162")/tcp_syn_ack)


	def wait_for_connection(self):
		sniff(iface="en0", prn=self.send_syn_ack, store=0, filter="tcp and port "+server_port)


if __name__ == "__main__":
	try:
		server = Server()
		server.wait_for_connection()
	except Exception as e:
		print(e)
