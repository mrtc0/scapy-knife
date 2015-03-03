#!/usr/bin/env python
# coding=utf-8

from scapy.all import *

class Scanner:
    # Scan Base Code
    
    def __init__(self, targetip, verbose=True):
        self.targetip = targetip
        self.results = {}

    def ReportResult(self):
        closedport = 0
        scannedport = len(self.results)
        print '[*]Result for %s ' % (self.targetip)
        print '    Port \t State'
        for k,v in sorted(self.results.iteritems()):
            if v == 'Closed':
                closedport += 1
            else:
                print '    %s \t %s' % (k, v)
        print 'Scanned %d ports, Closed %d ports. %s' % (scannedport, closedport, self.targetip)

    def Scan(self, ports):
        for port in list(ports):
            self.PortScan(port)
            #print port
        self.ReportResult()
    
    def PortScan(self, port):
        raise


class SYNScan(Scanner):
    def PortScan(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags="S"), verbose=False, timeout=5)
        if str(type(resp)) == "<type 'NoneType'>":
            self.results[port] = "Open | Filterd"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                rst = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags="R"), verbose=False, timeout=5)
                self.results[port] = "Open"
            elif resp.getlayer(TCP).flags == 0x14:
                self.results[port] = "Closed"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                self.results[port] = "Filtered"

class ACKScan(Scanner):
    def PortScan(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags="A"), verbose=False, timeout=5)
        if str(type(resp)) == "<type 'NoneType'>":
            self.results[port] = "Filterd (Statefull)"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x4:
                self.results[port] = "Unfilterd"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                self.results[port] = "Filtered (Statefull)"

class FINScan(Scanner):
    def PortScan(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags="F"), verbose=False, timeout=5)
        if str(type(resp)) == "<type 'NoneType'>":
            self.results[port] = "Open | Filterd"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:
                self.results[port] = "Closed"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                self.results[port] = "Filtered"

class XMASScan(Scanner):
    def PortScan(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags="FPU"), verbose=False, timeout=5)
        if str(type(resp)) == "<type 'NoneType'>":
            self.results[port] = "Open | Filterd"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:
                self.results[port] = "Closed"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                self.results[port] = "Filtered"

class NULLScan(Scanner):
    def PortScan(self, port):
        src_port = RandShort()
        resp = sr1(IP(dst=self.targetip)/TCP(sport=src_port, dport=port, flags=""), verbose=False, timeout=5)
        if str(type(resp)) == "<type 'NoneType'>":
            self.results[port] = "Open | Filterd"
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x14:
                self.results[port] = "Closed"
        elif resp.haslayer(ICMP):
            if int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                self.results[port] = "Filtered"

