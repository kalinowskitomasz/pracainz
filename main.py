#!/usr/bin/env python
from scapy.all import *
from client import *
import random
import binascii



if __name__ == "__main__":
    try:
        client = Client()
        client.handshake()
    except Exception as e:
        print(e)

