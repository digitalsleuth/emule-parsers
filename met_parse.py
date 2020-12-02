#!/usr/bin/env python3

"""
Parsing server.met file from eMule
http://wiki.amule.org/wiki/Server.met_file
https://github.com/irwir/eMule/blob/master/UDPSocket.cpp
https://github.com/irwir/eMule/blob/master/ServerList.cpp
"""
import struct, sys, socket
from argparse import ArgumentParser
from datetime import datetime as dt, timedelta

__author__ = 'Corey Forman'
__date__ = '14 Dec 2019'
__version__ = '1.2'
__description__ = 'eMule server.met file parser'

class MetError(Exception):
    pass

class HeaderMismatch(MetError):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

def metParse(input):
    met_header = 'e0'
    tag_ids = {
        '01':'Server Name',		#Name of the server
        '0b':'Description',		#Short description about the server
        '0c':'Ping',		        #Time in ms it takes to communicate with the server
        '0d':'Connect Fails',           #How many times connecting to the server has failed
        '0e':'Priority',		#Priority given to this server among the others (Normal=0, High=1, Low=2)
        '85':'Server DNS',		#DNS of the server
        '87':'Max Users',		#Maximum number of users the server allows to simultaneously connect
        '88':'Soft Files',		#Soft files number - minimum amount of files you must share on the server
        '89':'Hard Files',		#Hard files number - maximum amount of files you can share on the server
        '90':'Last Ping Time',	        #Last time the server was pinged - Unix 32-bit hex little endian timestamp
        '91':'Server SW Vers',	        #Version and name of the software the server is running 
        '92':'UDP Flags',		#UDP flags (see udp_flags dict) SRV_UDPFLG_EXT_GETSOURCES | SRV_UDPFLG_EXT_GETFILES | SRV_UDPFLG_NEWTAGS | SRV_UDPFLG_UNICODE | SRV_UDPFLG_EXT_GETSOURCES2 | SRV_UDPFLG_LARGEFILES | SRV_UDPFLG_UDPOBFUSCATION | SRV_UDPFLG_TCPOBFUSCATION
        '93':'Aux ports list',	        #Auxiliary ports list (additional ports for users who cannot connect to the standard one)
        '94':'LowID clients',	        #Number of users connected with a LowID
        '95':'Server UDP Key',          #95 unknown as of yet - github.com/irwir/eMule/blob/master/ServerList.cpp line 785 ?
        '96':'Host External IP',        #Current host external IP, referred to in ServerList.cpp as ServerKeyUDPIP (line 791)
        '97':'TCP Obfuscation Port',    #Obfuscation Port TCP
        '98':'UDP Obfuscation Port'}    #Obfuscation Port UDP 

    priorities = {0:'Normal',1:'High',2:'Low'}
    udp_flags = {'bit8':'Get sources','bit7':'Get files','bit6':'New tags','bit5':'Unicode','bit4':'Get extended source info','bit3':'Get large files','bit2':'Use UDP Obfuscation','bit1':'Use TCP Obfuscation'} #github.com/irwir/eMule/blob/master/ServerList.cpp
    file_header = input.read(1).hex()
    if file_header != met_header:
        raise HeaderMismatch("Invalid Server.Met file header - expected 'E0'")
    (server_count,) = struct.unpack('<I', input.read(4))
    print("Server Count: %d" % server_count)
    for i in range(server_count):
        server_ip = socket.inet_ntoa(struct.pack('!L', int(input.read(4).hex(), 16)))
        (server_port,) = struct.unpack('<H', input.read(2))
        (tag_count,) = struct.unpack('<I', input.read(4))
        print("Server IP: %s\tServer Port: %d\tTag Count: %d" % (server_ip, server_port, tag_count))
        for tag in range(tag_count):
            tag = input.read(1).hex()
            if tag == '02':
                tag_type = "String"
                (tag_name_length,) = struct.unpack('<H',input.read(2))
                if tag_name_length == 1:
                    tag_read = input.read(1).hex()
                    tag_name = tag_ids.get(tag_read)
                elif tag_name_length > 1:
                    tag_name = bytes.fromhex(input.read(tag_name_length).hex()).decode('utf-8')
                else:
                    print("Unidentified issue in tag_name_length")
                    raise SystemExit(1)
                (tag_value_length,) = struct.unpack('<H',input.read(2))
                tag_value = bytes.fromhex(input.read(tag_value_length).hex()).decode('utf-8')
                print("\t%s\t%s" % (tag_name, tag_value))
            elif tag == '03':
                UDP = []
                tag_type = "Numeric"
                (tag_name_length,) = struct.unpack('<H',input.read(2))
                if tag_name_length == 1:
                    tag_read = input.read(1).hex()
                    tag_name = tag_ids.get(tag_read)
                    if tag_read == '0e':
                        (priority,) = struct.unpack('<I', input.read(4))
                        tag_value = priorities.get(priority)
                    elif tag_read == '90':
                        (decimal_time,) = struct.unpack('<L', bytes.fromhex(input.read(4).hex()))
                        tag_value = dt.utcfromtimestamp(float(decimal_time)).strftime('%Y-%m-%d %H:%M:%S') + " UTC"
                    elif tag_read == '91':
                        tag_value_length = struct.unpack('<H',input.read(2))
                        tag_value = bytes.fromhex(input.read(tag_value_length).hex()).decode('utf-8')
                    elif tag_read == '92':
                        binary_dict = {'bit{}'.format(k): int(v) for k, v in enumerate('{:b}'.format(int(input.read(4).hex(), 16))[:-24], start=1)}
                        for i in range(1,9):
                            bit_value = 'bit' + str(i)
                            if binary_dict.get(bit_value) == 1:
                                UDP.insert(0,udp_flags.get(bit_value))
                        tag_value = UDP
                    elif tag_read == '96':
                        tag_value = socket.inet_ntoa(struct.pack('!L', int(input.read(4).hex(), 16)))
                    else:
                        (tag_value,) = struct.unpack('<I', input.read(4))
                elif tag_name_length > 1:
                    tag_name = bytes.fromhex(input.read(tag_name_length).hex()).decode('utf-8')
                    (tag_value,) = struct.unpack('<I', input.read(4))
                else:
                    print("Unidentified issue in tag_name_length")
                    raise SystemExit(1)
                print("\t%s\t%s" % (tag_name, tag_value))
            else:
                print("Unidentified tag value: %s.") % (tag)
                raise SystemExit(1)
if __name__ == "__main__":
    arg_parse = ArgumentParser(description="eMule server.met file parser")
    arg_parse.add_argument("met_file", help="server.met file to open")
    #arg_parse.add_argument("out_file", help="file and location to save output")
    arg_parse.add_argument("-v", action="version", version='%(prog)s' +' v' + str(__version__))
    args = arg_parse.parse_args()

    try:
        with open(args.met_file, 'rb') as metfile:
            metParse(metfile)
    except IOError as e:
        print("Unable to read '%s': %s" % (args.met_file, e), file=sys.stderr)
        raise SystemExit(1)