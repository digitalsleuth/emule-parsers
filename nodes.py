#!/usr/bin/env python3
"""
This code was originally found as an incomplete python2 script at the aMule wiki page:
http://wiki.amule.org/wiki/Nodes.dat_file
The script has been fixed, and ported to python 3
"""

import struct
import sys
from argparse import ArgumentParser

__author__ = "Corey Forman"
__date__ = "19 Dec 2019"
__version__ = "1.1"
__description__ = "Nodes.dat file parser for eMule/aMule installations"

def parse_nodes(dat_file):
    nodefile = open(dat_file, 'rb')
    nodefile.seek(4)
    (version,) = struct.unpack("<I", nodefile.read(4))
    (nodecount,) = struct.unpack("<I", nodefile.read(4))
    results = []
    if version == 0: #OLDER NODES.DAT needs to be verified and tested; parsing works, but data results not validated.
        header = 'idx\ttype\tIP address\tudp\ttcp'
        csvheader = 'idx,type,IP address,udp,tcp'
        for i in range(nodecount):
            (clientid, ip1, ip2, ip3, ip4, udpport, tcpport, type) = struct.unpack("<16s4BHHB", nodefile.read(25))
            ipaddr = '%d.%d.%d.%d' % (ip4, ip3, ip2, ip1)
            out = (i, type, ipaddr, udpport, tcpport)
            results.append(out)
        nodefile.close()
    elif version in range(1,3):
        header = 'idx\tVer\tIP address\tudp\ttcp\tkadUDPKey\t  verified'
        csvheader = 'idx,ver,IP address,udp,tcp,kadUDPKey,verified'
        for i in range(nodecount):
            (clientid, ip1, ip2, ip3, ip4, udpport, tcpport, type,  kadUDPkey, verified) = struct.unpack("<16s4BHHBQB", nodefile.read(34))
            ipaddr = '%d.%d.%d.%d' % (ip4, ip3, ip2, ip1)
            if (verified == 0): verf='N'
            else: verf='Y'
            out = (i, type, ipaddr, udpport, tcpport, '{:x}'.format(kadUDPkey), verf)
            results.append(out)
        nodefile.close()
    else:
        print('Unknown version: %d !' % (version))
        nodefile.close()
    return version, nodecount, header, csvheader, results
if __name__ == "__main__":
    arg_parse = ArgumentParser(description="eMule nodes.dat file parser")
    arg_parse.add_argument("dat_file", help="nodes.dat file to open")
    arg_parse.add_argument("-c", action="store_true", help="output in CSV format")
    arg_parse.add_argument("-v", action="version", version='%(prog)s' +' v' + str(__version__))
    args = arg_parse.parse_args()
    try:
        (version, nodecount, header, csvheader, results) = parse_nodes(args.dat_file)
        nodes_details = "Nodes.dat file version = %d\nNode count = %d\n" % (version, nodecount)
        if args.c:
            if version == 0:
                print(csvheader)
                for array in range(len(results)):
                    i, type, ipaddr, udpport, tcpport = results[array]
                    print('%d,%d,%s,%d,%d' % (i, type, ipaddr, udpport, tcpport))
            else:
                print(csvheader)
                for array in range(len(results)):
                    i, type, ipaddr, udpport, tcpport, kadUDPkey, verf = results[array]
                    print('%d,%d,%s,%d,%d,%s,%s' % (i, type, ipaddr, udpport, tcpport, kadUDPkey, verf))
        else:
            if version == 0:
                print(nodes_details)
                print(header)
                for array in range(len(results)):
                    i, type, ipaddr, udpport, tcpport = results[array]
                    print('%-4d\t%-4d\t%-15s\t%-5d\t%-5d' % (i, type, ipaddr, udpport, tcpport))
            else:
                print(nodes_details)
                print(header)
                for array in range(len(results)):
                    i, type, ipaddr, udpport, tcpport, kadUDPkey, verf = results[array]
                    print('%-4d\t%-3d\t%-15s\t%-5d\t%-5d\t%-16s\t%-s' % (i, type, ipaddr, udpport, tcpport, kadUDPkey, verf))
    except IOError as e:
        print("Unable to open file: %s" % (e))
        raise SystemExit(1)

