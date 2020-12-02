#!/usr/bin/env python3
#This will parse the preferencesKad.dat for an eMule client
#It is based on the following structure, found here:
#http://wiki.amule.org/wiki/PreferencesKad.dat_file

#4 bytes - IP ADDR (Little Endian)
#2 bytes - zero's (deprecated field)
#16 bytes - 4-byte byte-swaps - Client ID
#1 byte - End of tag (0x00)

import struct, sys, socket

if len(sys.argv) != 2:
    sys.exit("Please supply a preferencesKad.dat file!")

kadfile = open(sys.argv[1], 'rb')
ip = socket.inet_ntoa(struct.pack('!L',struct.unpack('<I', kadfile.read(4))[0]))
dep_val = kadfile.read(2).hex()
id_bytes = struct.unpack('<4I',kadfile.read(16))
id = ''
for index in range(len(id_bytes)):
    id = id + format(id_bytes[index],'x')
tag = kadfile.read(1).hex()

print("IP Address:\t ", ip)
print("Deprecated Value:", dep_val)
print("Client ID:\t ", id)
print("End Tag:\t ", tag)
