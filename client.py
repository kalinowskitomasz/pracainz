#!/usr/bin/env python

from scapy.all import *
import random
import common
import threading

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = 82

################################################################

class Receiver(AnsweringMachine):

	def __init__(self, sender, **kargs):
		self.filter="tcp dst port %d" % sender.source_port
		AnsweringMachine.__init__(self, **kargs)
		print "Receiver started	"

	################################################################

	def print_reply(self, req, reply):
		pass
		#print "message: "

	################################################################

	def is_request(self, req):
		#print "is request"
		return (req[TCP].flags & PSH) and (req[TCP].flags & ACK)

	################################################################

	def make_reply(self, req):
		ip = IP(dst=sender.server_ip)
		sender.ack += len(req[TCP].payload)
		tcp = TCP(flags="A", sport=sender.source_port, dport=req[TCP].sport, seq=sender.seq, ack=sender.ack)
		return ip/tcp

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
		self.__send_syn()
		return self.__send_ack()


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

	#############################################################

	def __send_ack(self):
		ip = IP(dst=self.server_ip)
		ack_pkt = ip / TCP(sport=self.source_port, dport=server_port, flags='A', seq=self.seq, ack=self.ack)
		send(ip / ack_pkt)
		return self.source_port

	#############################################################

	def send_message(self, message):
		data = 'zzzzzzz'
		opt_message = self.encode_options_field(message)
		#print "opt message: " + opt_message
		tcp = TCP(options=[(34, opt_message)], sport=self.source_port, dport=server_port, flags="PA", seq=self.seq, ack=self.ack)
		#print tcp[TCP].options
		pkt = IP(dst=self.server_ip) / tcp / Raw(load=data)
		ack_pkt = sr1(pkt)
		self.seq = ack_pkt[TCP].ack

	#############################################################


if __name__ == "__main__":
	sender = Sender()
	if sender.connect("192.168.1.193"):
		try:
			responder = Receiver(sender)
			t = threading.Thread(target=responder)
			t.setDaemon(True)
			t.start()
		except(KeyboardInterrupt, SystemExit):
			threading.cleanup_stop_thread()
			sys.exit()

	while True:
		msg = raw_input("> ")
		sender.send_message(msg)
		#sender.send_simple_message("bbbb")
