#!/usr/bin/env python
from scapy.all import *
from steg import *
import random
import binascii



if __name__ == "__main__":
    try:
        sender = Sender()
        sender.send()
    except Exception as e:
        print(e)

