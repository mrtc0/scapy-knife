#!/usr/bin/env python
# coding=utf-8
import sys
import simplejson
import urllib
import urllib2
from scapy.all import *

# set your VirusTotal API Key
vtapikey = ''

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


# Read pcap
pkt = rdpcap(sys.argv[1])

dnslist = [] # dns list from pcap
scanlist = [] # VirusTotal Scaned list

for p in pkt:
    if p.haslayer(DNSQR):
        if p[DNSQR].qname not in dnslist:
            dnslist.append(p[DNSQR].qname)

# VirusTotal url scan 
url = 'https://www.virustotal.com/vtapi/v2/url/report'


for host in dnslist:
    parameters = {'resource': host, 'apikey': vtapikey}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)
    response = urllib2.urlopen(req)
    scanlist.append(response.read())

for l in scanlist:
    try:
        rd = simplejson.loads(l)
        print colors['green'] + '[*] ' + rd.get('url') + colors['clear']
        for i in rd['scans'].keys():
            result = rd.get('scans', {}).get(i).get('result')
            if result == 'clean site' or result == 'unrated site':
                pass
            else:
                print '\t' + i + '\t' + colors['red'] + result + colors['clear']
    except:
        continue


