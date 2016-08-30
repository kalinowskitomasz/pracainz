#!/usr/bin/env python
from common import *
from scapy.all import *

server_port = "9000"
States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)
PktType = enum(SYN=0, SYNACK=1, ACK=2, PSH=3, RST=4)


class SocketManager:

	def __init__(self):
		self.sockets = {}

	#############################################################

	def on_packet_received(self, pkt):
		packet_type = SocketManager.packet_type(pkt)
		if packet_type == PktType.SYN:
			if pkt[TCP].sport in self.sockets:
				# error handling
				pass
			else:
				self.add_new_socket(self, pkt)

	#############################################################

	def add_new_socket(self, pkt):
		ip = pkt[IP].src
		port = pkt[TCP].sport
		seq = pkt[TCP].seq
		ack = pkt[TCP].ack
		self.sockets[port] = Socket(port, ip, ack, seq)

	#############################################################

	@staticmethod
	def packet_type(pkt):
		tcp = pkt.getlayer(TCP)
		return {
			tcp.flags & SYN & ACK: PktType.SYNACK,
			tcp.flags & SYN: PktType.SYN,
			tcp.flags & ACK: PktType.ACK
		}[pkt]

	#############################################################

	def is_syn(self, pkt):
		return pkt[TCP].flags & SYN


#############################################################


class Socket:
	connection_id = 0

	def __init__(self, port, ip, ack, seq):
		self.connection_id = Socket.connection_id
		Socket.connection_id += 1

		self.state = States.LISTENING

		self.port = port
		self.ip = ip
		self.ack = ack
		self.seq = seq


#############################################################

class CommunicationProvider(AnsweringMachine):

	function_name = "server"
	filter = "tcp port 9000"

	#############################################################

	def __init__(self, socket_manager):
		self.socket_manager = socket_manager

	#############################################################

	def is_request(self, req):

		self.socket_manager.on_packet_received(req)

		if self.is_syn(req):
			ip = req[IP].src
			port = req[TCP].sport
			ack = req[TCP].ack
			seq = req[TCP].seq
			self.socket_manager.on_new_connection(ip,port,ack,seq)







		if self.state == States.LISTENING:
			self.client_port = req[TCP].sport
			self.client_ip = req[IP].src

			self.state = States.SYN_RECEIVED
			#self.connection.set_filter("tcp dst port 9000 and tcp[tcpflags] & (tcp-ack) != 0 ")
			return True

		if self.state == States.SYN_RECEIVED:
			self.state = States.ESTABLISHED
			self.connection.set_filter("tcp dst port 9000 and tcp src port %d" % self.client_port)
			print "%d Connection Established" % self.id
			self.connection.on_established()
			return False


	#############################################################


	def print_reply(self, req, reply):
		print "Connection %d: %s ==> %s" % (self.id, req.summary(), reply.summary())

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
