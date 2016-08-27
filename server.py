#!/usr/bin/env python
from common import *
from scapy.all import *

interface = "en0"  # "en0"
server_port = "9000"
states = enum(NOT_CONNECTED=0, CONNECTING=1, CONNECTED=2, CONNECTION_ENDED=3)


class ConnectionManager:

	def __init__(self):
		self.sockets = []

	#############################################################

	def __call__(self):
		self.__start_listening()

	#############################################################

	def on_socket_connected(self):
		self.__start_new_listening_socket()

	#############################################################

	def	__start_new_listening_socket(self):
		self.sockets.append(Socket())
		self.sockets[-1]()

	#############################################################

	def __start_listening(self):
		self.sockets.append(Socket())
		self.sockets[0]()


class Socket(AnsweringMachine):

	function_name = "server"
	#filter = "tcp port " + server_port

	#############################################################

	def __init__(self, **kargs):
		AnsweringMachine.__init__(self, filter="tcp port 9000")
		self.state = states.NOT_CONNECTED
		self.client_port = None
		self.client_ip = None

	#############################################################

	def __del__(self):
		print "Connection on port %d ended" % self.client_port

	#############################################################

	def parse_options(self, joker="192.168.1.1", match=None):
		if match is None:
			self.match = {}
		else:
			self.match = match
		self.joker = joker

	#############################################################

	def is_request(self, req):
		if self.state == states.NOT_CONNECTED:
			flag = req['TCP'].flags
			if flag & SYN:
				req[TCP].dport = self.client_port
				req[IP].src = self.client_ip
				return True

		if self.state == states.CONNECTING:
			if self.state == states.NOT_CONNECTED:
				flag = req['TCP'].flags
				if flag & ACK:
					return True;

		if self.state == states.CONNECTED:
			return True

	#############################################################



	def make_reply(self, req):
		ans = IP(src=req[IP].dst, dst=req[IP].src) / TCP(
			flags='SA',
			sport=req[TCP].dport,
			dport=req[TCP].sport,
			seq=0,
			ack=req[TCP].seq + 1,
		)
		return ans


class Server3(AnsweringMachine):

	function_name = "server"
	filter = "tcp port " + server_port

	def __init__(self):
		self.is_connected = False

	# def send_syn_ack(self, pkt):
	# 	ans = IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP(
	# 		flags='SA',
	# 		sport=pkt[TCP].dport,
	# 		dport=pkt[TCP].sport,
	# 		seq=0,
	# 		ack=pkt[TCP].seq + 1,
	# 	)
	# 	return ans

	def make_reply(self, req):
		#if not self.is_connected:
			#ans = self.send_syn_ack(req)
		ans = IP(src=req[IP].dst, dst=req[IP].src) / TCP(
			flags='SA',
			sport=req[TCP].dport,
			dport=req[TCP].sport,
			seq=0,
			ack=req[TCP].seq + 1,
		)
		return ans



class Server2:

	def __init__(self):
		self.seq = 0
		self.ack = 0
		self.is_connected = False
		self.client_ip = None
		self.client_port = 12345

	#############################################################

	def __send_syn_ack(self):
		print "send syn ack"


	#############################################################

	def __on_packet_received(self, received_packet):
		print "aaaa"
		received_packet.show()
		flag = received_packet['TCP'].flags
		if flag & SYN:
			self.client_ip = received_packet['IP'].src
			self.client_port = received_packet['IP'].sport
			self.ack = received_packet['TCP'].ack
			#self.seq = received_packet['TCP'].data.length + 1
			#tcp_syn_ack = TCP(dport=self.client_port, sport=server_port, flags="SA", ack=self.seq, seq=self.ack)
			send(IP(dst=self.client_ip))

	#############################################################

	def wait_for_connection(self):
		sniff(iface=interface, prn=self.__on_packet_received, store=0, filter="tcp dst port 9000 ")

	#############################################################

	def rst(self, p):
		ans = IP(src=p[IP].dst, dst=p[IP].src) / TCP(
			flags='RA',
			sport=p[TCP].dport,
			dport=p[TCP].sport,
			seq=0,
			ack=p[TCP].seq + 1,
		)
		send(ans, verbose=False)
		#return "%s\n => %s" % (p[IP].summary(), ans.summary())

	def foo(self):
		sniff(iface="en0", filter="tcp and tcp[tcpflags] & tcp-syn == tcp-syn", prn=self.rst)

if __name__ == "__main__":
	try:
		comm_manager = ConnectionManager()
		comm_manager()

	except Exception as e:
		print(e)
