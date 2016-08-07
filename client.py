#!/usr/bin/env python
from scapy.all import *
import random
import common

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class Client:
	server_port = 9000

	def __init__(self, server_ip):
		self.server_ip = None
		self.seq = 0
		self.ack = 0
		self.sport = random.randint(1024, 65535)

	def connect(self,server_ip):
		self.server_ip = server_ip

		syn_ack = self.__send_syn()

		# SYN-ACK
		ACK = TCP(sport=sport, dport=80, flags='A', seq=syn_ack.__send_ack + 1, ack=syn_ack.seq + 1)
		send(ip / ACK)

		ip = IP(dst='192.168.1.75')
		tcp_syn = TCP(sport=12345, dport=9000, flags="S", ack=0, seq=0)
		tcp_ack = TCP(sport=12345, dport=9000, flags="A", ack=1, seq=1)
		sa = sr1(ip / tcp_syn)
		if sa['TCP'].flags & (syn & ACK):
			send(ip / tcp_ack)

	def __send_syn(self):
		ip = IP(dst=self.server_ip)
		self.seq = 0
		self.ack = 0
		syn = TCP(sport=sport, dport=80, flags='S', seq=self.seq, ack=self.ack)
		syn_ack = sr1(ip / syn)
		self.seq = syn_ack[ACK];

		return syn_ack

	def __send_ack(self,syn_ack):
		tcp = TCP(sport=send_port, dport=dest_port, flags="A", seq=Seq, ack=Ack)
		send(IP() / tcp)

	def send_simple_message(self):
		pkt = TCP(options=[(0, "aaaa")], sport=send_port, dport=dest_port, flags="A", seq=Seq, ack=Ack)
		send(IP() / pkt)

	def send(self):
		mask = random.randint(8, 255)
		ip = IP(src='192.168.1.162')
		message = "lorem ipsum"
		# message Buffer = chr(mask)
		message_buffer = ""
		for c in message:
			char_int = ord(c);
			message_buffer += chr(char_int ^ mask)
			# message_buffer+=chr(charInt)
			if len(message_buffer) == 38:
				# pkt = TCP(options=[(0, message_buffer)],flags="A")
				pkt = TCP(sport=32113, dport=80, flags=0)
				send(ip / pkt)
				message_buffer = ""
				print "packet sent"

		pkt = TCP(options=[(0, message_buffer)])
		send(ip / pkt)

	# print response


if __name__ == "__main__":
	try:
		client = Client()
		client.connect()
	except Exception as e:
		print(e)
