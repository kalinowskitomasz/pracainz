#!/usr/bin/env python
from common import *
from scapy.all import *
import threading

SERVER_PORT = 82
SERVER_SEND_PORT = SERVER_PORT + 1
States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)
PktType = enum(SYN=0, SYNACK=1, ACK=2, PSH=3, RST=4)


#############################################################

class SocketManager:

	def __init__(self):
		self.sockets = {}

	#############################################################

	def on_packet_received(self, pkt):
		packet_port = pkt[TCP].sport
		if packet_port in self.sockets:
			return self.sockets[packet_port].on_packet_received(pkt)
		elif self.is_syn(pkt):
			self.add_new_socket(pkt)
			return self.sockets[packet_port].on_syn_received(pkt)
		else:
			return None

	#############################################################

	def send_packet_to_socket(self, pkt):
		port = pkt[TCP].sport
		self.sockets[port].on_packet_received(pkt)

	#############################################################

	def add_new_socket(self, pkt):
		port = pkt[TCP].sport
		self.sockets[port] = Socket(pkt, self)

	#############################################################

	def send_message_to_all(self, pkt):
		message = decode_message(pkt)
		print "MESSAGE RECEIVED: " + message
		for port, sckt in self.sockets.iteritems():
			sckt.send_packet(pkt)

	#############################################################

	@staticmethod
	def is_syn(pkt):
		return pkt[TCP].flags & SYN


#############################################################

class Socket:
	connection_id = 0

	def __init__(self, pkt, socket_manager):
		self.socket_manager = socket_manager
		self.connection_id = Socket.connection_id
		Socket.connection_id += 1
		self.ip = pkt[IP].src
		self.port = pkt[TCP].sport
		self.ack = 0
		self.seq = 0

	#############################################################

	def send_packet(self, pkt):
		if pkt[TCP].sport != self.port:
			ip = IP(dst=self.ip)
			tcp = TCP(urgptr=pkt[TCP].urgptr, flags="PA", sport=SERVER_PORT, dport=self.port, seq=self.seq, ack=self.ack, options=pkt[TCP].options)
			data = pkt[Raw]
			pkt_to_send = ip/tcp/Raw(load=data)
			self.seq += len(data)
			send(pkt_to_send)

	#############################################################

	def on_packet_received(self, pkt):
		if (pkt[TCP].flags & PSH) and (pkt[TCP].flags & ACK):
			ip = IP(dst=pkt[IP].src)
			self.ack += len(pkt[TCP].payload)
			tcp = TCP(flags="A", sport=SERVER_PORT, dport=pkt[TCP].sport, seq=self.seq, ack=self.ack)
			ack_packet = ip/tcp
			return ack_packet

	#############################################################

	def send_message_to_all(self, pkt):
		# t = threading.Thread(target=self.socket_manager.send_message_to_all, args=pkt)
		# t.start()
		self.socket_manager.send_message_to_all(pkt)

	#############################################################

	def on_syn_received(self, pkt):
		self.port = pkt[TCP].sport
		self.ip = pkt[IP].src
		self.ack += 1
		ip = IP(dst=pkt[IP].src)
		tcp = TCP(urgptr=pkt.urgptr, flags="SA", sport=SERVER_PORT, dport=pkt[TCP].sport, seq=self.seq, ack=pkt[TCP].seq+1)
		self.seq = 1
		return ip / tcp

	#############################################################

	def __create_response(self, pkt):
		pass

#############################################################


class CommunicationProvider(AnsweringMachine):

	function_name = "server"
	filter = "tcp dst port %d" % SERVER_PORT

	#############################################################

	def __init__(self, **kargs):
		AnsweringMachine.__init__(self, verbose=False, **kargs)
		self.socket_manager = SocketManager()

	#############################################################

	def reply(self, pkt):
		response = self.socket_manager.on_packet_received(pkt)
		if response is None:
			return
		self.send_reply(response)
		if not pkt[TCP].flags & SYN:
			self.socket_manager.send_message_to_all(pkt)
		if conf.verb >= 0:
			self.print_reply(pkt, response)


if __name__ == "__main__":
	provider = CommunicationProvider()
	provider()
