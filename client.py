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

class Server:
	def synAck(pkt):
		F = pkt['TCP'].flags
		if F & SYN:
			tcpSynAck = TCP(dport = 12345, sport = 80, flags = "SA", ack = 0,seq = 1 )
			send(IP(dst = '192.168.1.162')/tcpSynAck1)

	def waitForConnection(self):
		sniff(iface="eth0", prn=synAck, store=0)
		#tcp2 = TCP(dport = 12345, sport = 80, flags = "SA", ack = 0,seq = 1 )

##############################################################################

class Client:

	def handshake(self):
		sport = random.randint(1024,65535)
		# SYN
		ip=IP(dst='127.0.0.1')
		SYN=TCP(sport=sport,dport=80,flags='S',seq=1000)
		SYNACK=sr1(ip/SYN)
		# SYN-ACK
		ACK=TCP(sport=sport, dport=80, flags='A', seq=SYNACK.ack + 1, ack=SYNACK.seq + 1)
		send(ip/ACK)

		ip = IP(dst = '192.168.1.75')
		tcpSyn = TCP(sport = 12345, dport = 9000, flags = "S", ack = 0,seq = 0 )
		tcpAck = TCP(sport = 12345, dport = 9000, flags = "A", ack = 1,seq = 1 )
		sa = sr1(ip/tcpSyn)
		if sa['TCP'].flags & (SYN & ACK):
			send(ip/tcpAck)

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

if __name__ == "__main__":
    try:
        client = Client()
        client.handshake()
    except Exception as e:
        print(e)
