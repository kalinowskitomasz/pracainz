#!/usr/bin/env python
from scapy.all import *
import random
import binascii

class Sender:

	def handshake(self):
		tcp1 = TCP(sport = 12345, dport = 80, flags = "S", ack = 0,seq = 0 )
		tcp2 = TCP(dport = 12345, sport = 80, flags = "SA", ack = 0,seq = 1 )
		tcp3 = TCP(sport = 12345, dport = 80, flags = "A", ack = 1,seq = 1 )
		send(IP()/tcp1)
		send(IP()/tcp2)
		send(IP()/tcp3)

	def ack(sendPort,destPort,Ack,Seq):
		tcp = TCP(sport = sendPort, dport = destPort, flags = "A",seq=Seq,ack = Ack)
		send(IP()/tcp)

	def sendSimpleMessage(self):
		pkt = TCP(options=[(0, "aaaa")],sport = sendPort, dport = destPort, flags = "A",seq=Seq,ack = Ack)
		send(IP()/pkt)

	def send(self):
		mask = random.randint(8,255)
		ip = IP(src='192.168.1.162')
		message = "lorem ipsum"
		#message Buffer = chr(mask)
		messageBuffer=""
		for c in message:
			charInt = ord(c);
			messageBuffer+= chr(charInt ^ mask)
			#messageBuffer+=chr(charInt)
			if len(messageBuffer) == 38:
				#pkt = TCP(options=[(0, messageBuffer)],flags="A")
				pkt = TCP(sport=32113, dport =80,flags=0)
				send(ip/pkt)
				messageBuffer = ""
				print "packet sent"

		pkt = TCP(options=[(0, messageBuffer)])
		send(ip/pkt)
		#print response