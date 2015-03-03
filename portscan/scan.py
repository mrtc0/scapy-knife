#!/usr/bin/env python
# coding=utf-8

import argparse
from tcpscan import *
from commonports import COMMON_PORTS


scanners = []
ports =[]
targetip = True
verbose = True


def cmdparser():
    global scanners, ports, targetip, verbose
    progname = __file__
    usage = '%s -t <target IP> <options>\n' % progname

    parser = argparse.ArgumentParser(usage=usage, prog=progname)

    parser.add_argument('-t', dest='targetip', help='Target IP Address', required=True)
    parser.add_argument('-p', '--port', dest='ports', default=None, help='Scan Port')
    parser.add_argument('-S', '--syn', dest='synflag', action='store_true', help='TCP SYN SCAN')
    parser.add_argument('-A', '--ack', dest='ackflag', action='store_true', help='TCP ACK SCAN')
    parser.add_argument('-F', '--fin', dest='finflag', action='store_true', help='TCP FIN SCAN')
    parser.add_argument('-X', '--xmas', dest='xmasflag', action='store_true', help='TCP XMAS SCAN')
    parser.add_argument('-N', '--null', dest='nullflag', action='store_true', help='TCP NULL SCAN')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose')

    args = parser.parse_args()
    targetip = args.targetip

    validarg = (args.synflag or args.ackflag or args.finflag or args.xmasflag or args.nullflag)

    if not validarg:
        parser.error('Please set flag [-S, -A, -F, -X, -N]')
        
    else:
        if args.synflag:
            scanners.append( (SYNScan) )
        if args.ackflag:
            scanners.append( (ACKScan) )
        if args.finflag:
            scanners.append( (FINScan) )
        if args.xmasflag:
            scanners.append( (XMASScan) )
        if args.nullflag:
            scanners.append( (NULLScan) )


    verbose = args.verbose
    
    if args.ports:
        ports = args.ports.split(',')
        ports = map(int,ports)
    else:
        ports = COMMON_PORTS.keys()

if __name__ == "__main__":
    cmdparser()
    for scanner in scanners:
        s = scanner(targetip, verbose=verbose)
        s.Scan(ports)










