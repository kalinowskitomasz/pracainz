#!/usr/bin/env python
from common import *
from scapy.all import *

SERVER_PORT = 9000
States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)
PktType = enum(SYN=0, SYNACK=1, ACK=2, PSH=3, RST=4)


class SocketManager:

	def __init__(self):
		self.sockets = {}

	#############################################################

	def on_packet_received(self, pkt):
		if pkt[TCP].sport in self.sockets:
			return self.sockets[pkt[TCP].sport].on_packet_received(pkt)
		elif self.is_syn(pkt):
			self.add_new_socket(pkt)
			return self.sockets[pkt[TCP].sport].on_syn_received(pkt)
		else:
			return None

	#############################################################

	def send_packet_to_socket(self, pkt):
		port = pkt[TCP].sport
		self.sockets[port].on_packet_received(pkt)

	#############################################################

	def add_new_socket(self, pkt):
		port = pkt[TCP].sport
		self.sockets[port] = Socket(pkt)

	#############################################################

	@staticmethod
	def is_syn(pkt):
		return pkt[TCP].flags & SYN


#############################################################


class Socket:
	connection_id = 0

	def __init__(self, pkt):

		self.connection_id = Socket.connection_id
		Socket.connection_id += 1
		self.ip = None
		self.port = None

	def on_packet_received(self, pkt):
		self.__create_response(pkt)

	def on_syn_received(self, pkt):
		self.port = pkt[TCP].sport
		self.ip = pkt[IP].src

		ip = IP(dst=pkt[IP].src)
		tcp = TCP(flags="SA", sport=SERVER_PORT, dport=pkt[TCP].sport, seq=0, ack=pkt[TCP].seq+1)
		retVal = ip / tcp
		return retVal

	def __create_response(self, pkt):
		pass

#############################################################


class CommunicationProvider(AnsweringMachine):

	function_name = "server"
	filter = "tcp port 9000"

	#############################################################

	def __init__(self, **kargs):
		AnsweringMachine.__init__(self, **kargs)
		self.socket_manager = SocketManager()

	#############################################################

	def is_request(self, req):
		self.socket_manager.on_packet_received(req)

	#############################################################

	# def print_reply(self, req, reply):
	# 	print "Connection %d: %s ==> %s" % (self.id, req.summary(), reply.summary())

	#############################################################

	def make_reply(self, req):
		return self.socket_manager.on_packet_received(req)

	def reply(self, pkt):
		response = self.socket_manager.on_packet_received(pkt)
		if response is None:
			return
		#reply = self.make_reply(pkt)
		self.send_reply(response)
		if conf.verb >= 0:
			self.print_reply(pkt, response)


if __name__ == "__main__":
	provider = CommunicationProvider()
	provider()
