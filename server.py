#!/usr/bin/env python
from scapy.all import *
import common

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = "9000"
interface = "en0"  # "en0"

class Server:

	def __init__(self):
		self.seq = 0
		self.ack = 0
		self.is_connected = False
		self.client_ip = None
		self.client_port = 12345

	#############################################################

	def __send_syn_ack(self):
		print "send syn ack"
		tcp_syn_ack = TCP(dport=self.destination_port, sport=server_port, flags="SA", ack=self.seq, seq=self.ack)
		send(IP(dst=self.client_ip) / tcp_syn_ack)

	#############################################################

	def __on_packet_received(self, received_packet):
		print "aaaa"
		received_packet.show()
		flag = received_packet['TCP'].flags
		if flag & SYN:
			self.client_ip = received_packet['IP'].src
			self.client_port = received_packet['IP'].sport
			self.ack = received_packet['TCP'].ack
			self.seq = received_packet['TCP'].data.length + 1
			self.__send_syn_ack()

	#############################################################

	def wait_for_connection(self):
		sniff(iface=interface, prn=self.__on_packet_received, store=0, filter="tcp dst port 9000 ")

	#############################################################


if __name__ == "__main__":
	try:
		server = Server()
		server.wait_for_connection()
	except Exception as e:
		print(e)
