#!/usr/bin/env python
from scapy.all import *
import random
import binascii

class Sender:

    def send(self):
        mask = random.randint(8,255)
        ip = IP(src='192.168.1.162')
        message = "lorem ipsum"
        #messageBuffer = chr(mask)
        messageBuffer=""
        for c in message:
            charInt = ord(c);
            messageBuffer+= chr(charInt ^ mask)
            #messageBuffer+=chr(charInt)
            if len(messageBuffer) == 38:
                pkt = TCP(options=[(0, messageBuffer)])
                send(ip/pkt)
                messageBuffer = ""
                print "packet sent"

        pkt = TCP(options=[(0, messageBuffer)])
        response = sr1(ip/pkt)
        print response

    #def recieve(self):
