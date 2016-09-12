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

server_port = 9000


class Receiver(AnsweringMachine):
	def __init__(self):
		pass


################################################################

class Sender:
	def __init__(self):
		self.server_ip = None
		self.seq = 0
		self.ack = 0
		self.source_port = random.randint(49152, 65535)

	#############################################################

	def reset_connection(self):
		self.seq = 0
		self.ack = 0

	#############################################################

	def connect(self, server_ip):
		self.server_ip = server_ip
		self.server_ip = server_ip
		self.__send_syn()
		self.__send_ack()

	#############################################################

	def __send_syn(self):
		ip = IP(dst=self.server_ip)
		self.seq = 0
		self.ack = 0
		syn = ip / TCP(sport=self.source_port, dport=server_port, flags='S', seq=self.seq, ack=self.ack)
		ls(syn)
		syn_ack = sr1(syn)
		self.seq = syn_ack.ack
		self.ack = syn_ack.seq + 1
		return syn_ack

	#############################################################

	def __send_ack(self):
		ip = IP(dst=self.server_ip)
		ack_pkt = ip / TCP(sport=self.source_port, dport=server_port, flags='A', seq=self.seq, ack=self.ack)
		send(ip / ack_pkt)

	#############################################################

	def send_simple_message(self):
		pkt = TCP(options=[(0, "aaaaaaaaaaaa")], sport=self.source_port, dport=server_port, flags="PA", seq=1, ack=1)
		send(IP(dst = self.server_ip) / pkt)

	#############################################################

	def send(self):
		mask = random.randint(8, 255)
		ip = IP(src='192.168.1.162')
		message = "lorem ipsum"
		# message Buffer = chr(mask)
		message_buffer = ""
		for c in message:
			char_int = ord(c)
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

	#############################################################


if __name__ == "__main__":
	try:
		sender = Sender()
		sender.connect("192.168.1.75")
		sender.send_simple_message()
	except Exception as e:
		print(e)
