#!/usr/bin/env python
# coding=utf-8

from scapy.all import *

def sendSA(p):
    if str(type(p)) != "<type 'NoneType'>":
        if p.haslayer(TCP):
            if p.getlayer(TCP).flags == 0x02:
                sendp = IP(dst=p.getlayer(IP).src)/\
                        TCP(dport=p.getlayer(TCP).sport, sport=p.getlayer(TCP).dport, \
                        flags=0x12, ack=p.getlayer(TCP).seq+1, seq=p.getlayer(TCP).seq )
                send(sendp)

sniff(filter="tcp", prn=sendSA)
