#!/usr/bin/env python
from scapy.all import *
import random
from abc import ABCMeta, abstractmethod

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

server_port = "9000"


def generate_data(n):
	return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(n))


def enum(**enums):
	return type('Enum', (), enums)

States = enum(LISTENING=0, SYN_SENT=1, SYN_RECEIVED=2, ESTABLISHED=3)

class Observable(object):
	def __init__(self):
		self.observers = []

	def register(self, observer):
		if not observer in self.observers:
			self.observers.append(observer)

	def unregister(self, observer):
		if observer in self.observers:
			self.observers.remove(observer)

	def unregister_all(self):
		if self.observers:
			del self.observers[:]

	def update_observers(self, *args, **kwargs):
		for observer in self.observers:
			observer.update(*args, **kwargs)


class Observer(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def update(self, *args, **kwargs):
		pass

