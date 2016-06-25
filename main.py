#!/usr/bin/env python
from scapy.all import *
from steg import *
import random
import binascii



if __name__ == "__main__":
    try:
        server = Server()
        server.waitForConnection()
    except Exception as e:
        print(e)

