#!/usr/bin/env python
# coding=utf-8

import re
import subprocess
from scapy.all import *

def arp_display(pkt):
    if pkt[ARP].op == 1: # ARP Request
        print "Request: %s -> %s  " % (pkt[ARP].psrc, pkt[ARP].pdst)
    if pkt[ARP].op == 2: # ARP Reply
        try: 
            if pkt[ARP].hwsrc != im_dic[pkt[ARP].psrc]:
                print colors['red'] + "[*] Detect Spoofing!!" + colors['clear']
                print colors['red'] + "[*] %s : %s to %s" % (pkt[ARP].psrc, im_dic[pkt[ARP].psrc], pkt[ARP].hwsrc) + colors['clear']
        except:
            pass
        print "Reply: %s -> %s " % (pkt[ARP].hwsrc, pkt[ARP].psrc)


# Terminal colors
colors = {
    'clear': '\033[0m',
    'black': '\033[30m',
    'red': '\033[31m',
    'green': '\033[32m',
    'yellow': '\033[33m',
    'blue': '\033[34m',
    'purple': '\033[35m',
    'cyan': '\033[36m',
    'white': '\033[37m'
}

cmd_arpip = "cat /proc/net/arp | awk '{print $1}'"
cmd_arpmac = "cat /proc/net/arp | awk '{print $4}'"

ipl = subprocess.check_output(cmd_arpip, shell=True)
macl = subprocess.check_output(cmd_arpmac, shell=True)

re_ipaddr = re.compile("((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))")
re_macaddr = re.compile("^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")

im_dic = {}
for (ip, mac) in zip(ipl.split('\n'), macl.split('\n')):
    mip = re_ipaddr.search(ip)
    mmac = re_macaddr.search(mac)
    if mip is not None: 
        im_dic.update({mip.group():mmac.group()})        

print im_dic

sniff(prn=arp_display, filter="arp")
 

