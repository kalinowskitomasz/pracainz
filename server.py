#!/usr/bin/env python

from common import *
from scapy.all import *


interface = "en0"  # "en0"
server_port = "9000"
States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)


class ConnectionManager:

	def __init__(self):
		self.connections = []

	#############################################################

	def __call__(self):
		self.__start_listening()

	#############################################################

	def on_socket_connected(self):
		self.__start_new_listening_connection()

	#############################################################

	def	__start_new_listening_socket(self):
		self.connections.append(Connection(self))
		self.connecitons[-1]()

	#############################################################

	def __start_listening(self):
		self.connections.append(Connection(self))
		self.connections[0]()

#############################################################


class Connection:

	def __init__(self, connection_manager):
		self.connection_manager = connection_manager
		self.socket = Socket(self)

	def __call__(self):
		self.socket()

	def set_filter(self, new_filter):
		self.socket.filter = new_filter

#############################################################


class Socket(AnsweringMachine):

	function_name = "server"
	#filter = "tcp port " + server_port

	#############################################################

	def __init__(self, connection):
		AnsweringMachine.__init__(self, filter="tcp dst port 9000 and tcp[tcpflags] & (tcp-syn) != 0 ")
		self.connection = connection
		self.state = States.LISTENING
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
		if self.state == States.LISTENING:
			self.client_port = req[TCP].sport
			self.client_ip = req[IP].src

			self.state = States.SYN_RECEIVED
			self.connection.set_filter("tcp dst port 9000 and tcp[tcpflags] & (tcp-syn) != 0 ")
			return True

		if self.state == States.SYN_RECEIVED:
			self.filter = States.ESTABLISHED
			self.connection.set_filter("tcp dst port 9000 and tcp src port %d" % self.client_port)
			print "Connection Established"
			return False

	#############################################################

	def make_reply(self, req):
		if self.state == States.SYN_RECEIVED:
			ans = IP(src=req['IP'].dst, dst=req['IP'].src) / TCP(
				flags='SA',
				sport=req['TCP'].dport,
				dport=req['TCP'].sport,
				seq=0,
				ack=req['TCP'].seq + 1,
			)
			self.state == States.SYN_RECEIVED
			return ans


if __name__ == "__main__":
	#try:
	comm_manager = ConnectionManager()
	comm_manager()

	#except Exception as e:
#		print(e)
