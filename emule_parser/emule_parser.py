#!/usr/bin/env python3

"""
This script parses the server.met file from eMule and aMule applications.
The following URL's were used as reference material for the build of this script.
http://wiki.amule.org/wiki/Server.met_file
https://github.com/irwir/eMule/blob/master/UDPSocket.cpp
https://github.com/irwir/eMule/blob/master/ServerList.cpp
"""
import struct
import sys
import socket
import os
import json
import configparser
from argparse import ArgumentParser
from datetime import datetime as dt

__author__ = "Corey Forman"
__date__ = "8 Dec 2024"
__version__ = "2.0"
__description__ = "eMule/aMule file parser"

MET_HEADER = "e0"

class MetError(Exception):
    pass


class HeaderMismatch(MetError):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message


def process(isdir, isfile):
    CAN_PROCESS = [
        "addresses.dat",
        "amulesig.dat",
        "emulesig.dat",
        "canceled.met",
        "clients.met",
        "preferencesKad.dat",
        "server.met",
        "nodes.dat",
        "amule.conf",
        "emule.conf",
        "remote.conf",
        "ED2KLinks"
    ]
    WILL_PROCESS = []
    RESULTS = {}
    if isdir:
        dirname = isdir
        dir_listing = os.listdir(dirname)
        for file in dir_listing:
            if file in CAN_PROCESS:
                WILL_PROCESS.append(f"{dirname}{file}")
    if isfile:
        filename = isfile
        if os.path.basename(filename) in CAN_PROCESS:
            WILL_PROCESS.append(filename)

    if not WILL_PROCESS:
        print("[!] No supported files found, exiting.")
        raise SystemExit(1)

    for entry in WILL_PROCESS:
        if "address" in os.path.basename(entry):
            processed = addresses(entry)
        if "mulesig" in os.path.basename(entry):
            processed = mulesig(entry)
        if "canceled" in os.path.basename(entry):
            processed = canceled(entry)
        if "preferencesKad" in os.path.basename(entry):
            processed = pref_kad(entry)
        if "server.met" in os.path.basename(entry):
            processed = server_met(entry)
        if "nodes.dat" in os.path.basename(entry):
            processed = nodes(entry)
        if ".conf" in os.path.basename(entry):
            processed = config_file(entry)
        if "ED2KLinks" in os.path.basename(entry):
            processed = ed2k_links(entry)
        if "clients" in os.path.basename(entry):
            processed = clients_met(entry)
        RESULTS[entry] = processed

    return RESULTS


def ed2k_links(ed2k_file):
    RESULT = {}
    RESULT["File"] = ed2k_file
    RESULT["Links"] = {}
    with open(ed2k_file) as file:
        content = file.readlines()
    for line in content:
        idx = content.index(line)
        RESULT["Links"][idx] = {}
        line = line.split('|')
        if len(line) == 6:
            prefix, link_type, name, size, md4_hash, addl_content = line
        elif len(line) == 7:
            prefix, link_type, name, size, md4_hash, part_root_hash, addl_content = line
            RESULT["Links"][idx]["Partial or Root Hash"] = part_root_hash
        elif len(line) == 8:
            prefix, link_type, name, size, md4_hash, sep, sources, addl_content = line
            RESULT["Links"][idx]["Sources"] = sources
        addl_content = addl_content.rstrip()
        RESULT["Links"][idx]["Name"] = name
        RESULT["Links"][idx]["File Size"] = size
        RESULT["Links"][idx]["MD4 Hash"] = md4_hash
        RESULT["Links"][idx]["Addl Content"] = addl_content
    return RESULT


def config_file(config, start=0, ERRORS=None):
    RESULT = {}
    RESULT["File"] = config
    RESULT["Content"] = {}
    RESULT["Parsing Errors"] = {}  
    conf_obj = configparser.ConfigParser(interpolation=None, allow_no_value=True)
    try:
      
        with open(config, 'r') as conf_file:
            if start != 0:
                content = conf_file.readlines()[start - 1:]
                conf_str = ''.join(content)
                conf_obj.read_string(conf_str)
                RESULT["Parsing Errors"] = ERRORS["Parsing Errors"]
            else:
                conf_obj.read_file(conf_file)
        sections = conf_obj.sections()
        for section in sections:
            items = conf_obj.items(section)
            RESULT["Content"][section] = dict(items)
    except configparser.MissingSectionHeaderError as e:
        ERRORS = {}
        ERRORS["Parsing Errors"] = {}
        ERRORS["Parsing Errors"][f"Line {e.lineno}"] = {"Error": str(e), "Line Content": e.line}
        RESULT = config_file(config, e.lineno + 1, ERRORS)
    return RESULT


def server_met(met_file):
    servers = {}
    tag_ids = {
        "01": "Server Name",  # Name of the server
        "0b": "Description",  # Short description about the server
        "0c": "Ping",  # Time in ms it takes to communicate with the server
        "0d": "Connect Fails",  # How many times connecting to the server has failed
        "0e": "Priority",  # Priority given to this server among the others (Normal=0, High=1, Low=2)
        "85": "Server DNS",  # DNS of the server
        "87": "Max Users",  # Maximum number of users the server allows to simultaneously connect
        "88": "Soft Files",  # Soft files number - minimum amount of files you must share on the server
        "89": "Hard Files",  # Hard files number - maximum amount of files you can share on the server
        "90": "Last Ping Time",  # Last time the server was pinged - Unix 32-bit hex little endian timestamp
        "91": "Server SW Vers",  # Version and name of the software the server is running
        "92": "UDP Flags",  # UDP flags (see udp_flags dict) - Source flags obtained from UDP Socket cpp reference above.
        "93": "Aux ports list",  # Auxiliary ports list (additional ports for users who cannot connect to the standard one)
        "94": "LowID clients",  # Number of users connected with a LowID
        "95": "Server UDP Key",  # Server UDP Key as decimal - github.com/irwir/eMule/blob/master/ServerList.cpp line 785
        "96": "Host External IP",  # Current host external IP, referred to in ServerList.cpp as ServerKeyUDPIP (line 791)
        "97": "TCP Obfuscation Port",  # Obfuscation Port TCP
        "98": "UDP Obfuscation Port",  # Obfuscation Port UDP
    }
    priorities = {
        0: "Normal",  # default value, will not be present if priority not changed
        1: "High",  # user preference for high priority server upon connection/download
        2: "Low",  # user preference to identify lower priority server
    }
    udp_flags = {
        # Typical value is 'FB' which is 11111011 in binary. From right to left (little endian/LSB)
        # Therefore bit8 = LSB (right-most bit), bit1 = MSB (left-most bit)
        # github.com/irwir/eMule/blob/master/ServerList.cpp
        "bit8": "Get sources",  #  Right-most bit
        "bit7": "Get files",
        "bit6": "New tags",
        "bit5": "Unicode",
        "bit4": "Get extended source info",
        "bit3": "Get large files",
        "bit2": "Use UDP Obfuscation",
        "bit1": "Use TCP Obfuscation",
    }
    infile = open(met_file, "rb")
    file_size = os.fstat(infile.fileno()).st_size
    file_header = infile.read(1).hex()
    if file_header != MET_HEADER:
        raise HeaderMismatch("Invalid Server.Met file header - expected 'E0'")
    (server_count,) = struct.unpack("<I", infile.read(4))
    servers["Server Count"] = server_count
    servers["Servers"] = {}

    for server in range(server_count):
        servers["Servers"][str(server)] = {}
        server_ip = socket.inet_ntoa(struct.pack("!L", int(infile.read(4).hex(), 16)))
        (server_port,) = struct.unpack("<H", infile.read(2))
        (tag_count,) = struct.unpack("<I", infile.read(4))
        servers["Servers"][str(server)]["IP"] = server_ip
        servers["Servers"][str(server)]["Port"] = server_port
        servers["Servers"][str(server)]["Tag Count"] = tag_count
        servers["Servers"][str(server)]["Tags"] = {}
        for each in range(tag_count):
            tag = infile.read(1).hex()
            if tag == "02":
                servers["Servers"][str(server)]["Tags"][str(each)] = {}
                servers["Servers"][str(server)]["Tags"][str(each)]["Tag"] = tag
                tag_type = "String"
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Type"
                ] = tag_type
                (tag_name_length,) = struct.unpack("<H", infile.read(2))
                if tag_name_length == 1:
                    tag_read = infile.read(1).hex()
                    tag_name = tag_ids.get(tag_read)
                elif tag_name_length > 1:
                    tag_name = bytes.fromhex(infile.read(tag_name_length).hex()).decode(
                        "utf-8"
                    )
                else:
                    print("Unidentified issue in tag_name_length")
                    raise SystemExit(1)
                (tag_value_length,) = struct.unpack("<H", infile.read(2))
                tag_value = bytes.fromhex(infile.read(tag_value_length).hex()).decode(
                    "utf-8"
                )
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Name"
                ] = tag_name
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Value"
                ] = tag_value
            elif tag == "03":
                servers["Servers"][str(server)]["Tags"][str(each)] = {}
                servers["Servers"][str(server)]["Tags"][str(each)]["Tag"] = tag
                UDP = []
                tag_type = "Numeric"
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Type"
                ] = tag_type
                (tag_name_length,) = struct.unpack("<H", infile.read(2))
                if tag_name_length == 1:
                    tag_read = infile.read(1).hex()
                    tag_name = tag_ids.get(tag_read)
                    if tag_read == "0e":
                        (priority,) = struct.unpack("<I", infile.read(4))
                        tag_value = priorities.get(priority)
                    elif tag_read == "90":
                        (decimal_time,) = struct.unpack(
                            "<L", bytes.fromhex(infile.read(4).hex())
                        )
                        tag_value = (
                            dt.utcfromtimestamp(float(decimal_time)).strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )
                            + " UTC"
                        )
                    elif tag_read == "91":
                        tag_value_length = struct.unpack("<H", infile.read(2))
                        tag_value = bytes.fromhex(
                            infile.read(tag_value_length).hex()
                        ).decode("utf-8")
                    elif tag_read == "92":
                        binary_dict = {
                            f"bit{k}": int(v)
                            for k, v in enumerate(
                                "{:b}".format(int(infile.read(4).hex(), 16))[:-24],
                                start=1,
                            )
                        }
                        for i in range(1, 9):
                            bit_value = f"bit{str(i)}"
                            if binary_dict.get(bit_value) == 1:
                                UDP.insert(0, udp_flags.get(bit_value))
                        tag_value = ", ".join(str(s) for s in UDP)
                    elif tag_read == "96":
                        tag_value = socket.inet_ntoa(
                            struct.pack("!L", int(infile.read(4).hex(), 16))
                        )
                    else:
                        (tag_value,) = struct.unpack("<I", infile.read(4))
                elif tag_name_length > 1:
                    tag_name = bytes.fromhex(infile.read(tag_name_length).hex()).decode(
                        "utf-8"
                    )
                    (tag_value,) = struct.unpack("<I", infile.read(4))
                else:
                    print("Unidentified issue in tag_name_length")
                    raise SystemExit(1)
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Name"
                ] = tag_name
                servers["Servers"][str(server)]["Tags"][str(each)][
                    "Tag Value"
                ] = tag_value
            elif tag == "":
                break
            else:
                print(f"Unidentified tag value: {tag}.")
                raise SystemExit(1)
    return servers

def clients_met(clients):
    RESULT = {}
    RESULT["File"] = clients
    RESULT["Clients"] = {}
    hash_padding = None
    sid_hash = None
    with open(clients, 'rb') as met_file:
        clients_size = os.fstat(met_file.fileno()).st_size
        (version, ) = struct.unpack('B', met_file.read(1))
        (num_clients, ) = struct.unpack('I', met_file.read(4))
        for client in range(num_clients - 1):
            user_hash, low_up_to, low_down_fr, dt_client_id, high_up_to, high_down_fr, rsrvd, sid_hash_size, sid_hash_content = struct.unpack('<16s5IhB80s', met_file.read(119))
            user_hash = user_hash.hex()
            total_up = high_up_to * 2**32 + low_up_to
            total_down = high_down_fr * 2**32 + low_down_fr
            dt_client_id = f'{dt.utcfromtimestamp(float(dt_client_id)).strftime("%Y-%m-%d %H:%M:%S")} UTC'
            if len(sid_hash_content) > sid_hash_size:
                sid_hash = sid_hash_content[:sid_hash_size].hex()
                hash_padding = sid_hash_content[sid_hash_size:].hex()
            RESULT["Clients"][client] = {"User Hash": user_hash, "Total Uploaded to Client": total_up, "Total Downloaded from Client": total_down, "Date Client last ID'd": dt_client_id, "SID Hash": sid_hash, "Hash Padding": hash_padding}
            offset = met_file.tell()
            remainder = clients_size - offset
            if remainder < 119:
                (remaining_bytes, ) = struct.unpack(f"<{remainder}s", met_file.read(remainder))
                RESULT[f"Remaining {remainder } Bytes"] = remaining_bytes.hex()
                break
    return RESULT

def pref_kad(kad):
    RESULT = {}
    RESULT["File"] = kad
    kadfile = open(kad, "rb")
    ip = socket.inet_ntoa(struct.pack("!L", struct.unpack("<I", kadfile.read(4))[0]))
    dep_val = kadfile.read(2).hex()
    id_bytes = struct.unpack("<4I", kadfile.read(16))
    idval = ""
    for index in range(len(id_bytes)):
        idval = idval + format(id_bytes[index], "x")
    tag = kadfile.read(1).hex()
    RESULT["Data"] = {
        "IP": ip,
        "Deprecated Value": dep_val,
        "Client ID": idval,
        "End Tag": tag,
    }
    return RESULT


def nodes(dat_file):
    RESULT = {}
    RESULT["File"] = dat_file
    with open(dat_file, "rb") as nodefile:
        nodefile.seek(4)
        (version,) = struct.unpack("<I", nodefile.read(4))
        (nodecount,) = struct.unpack("<I", nodefile.read(4))
        RESULT["Version"] = version
        RESULT["Node Count"] = nodecount
        RESULT["Nodes"] = {}
        if (
            version == 0
        ):  # OLDER NODES.DAT needs to be verified and tested; parsing works, but data results not validated.
            for i in range(nodecount):
                (clientid, ip1, ip2, ip3, ip4, udpport, tcpport, typeval) = (
                    struct.unpack("<16s4BHHB", nodefile.read(25))
                )
                ipaddr = f"{ip4}.{ip3}.{ip2}.{ip1}"
                RESULT["Nodes"][i] = {
                    "Client ID": clientid.hex(),
                    "Type": typeval,
                    "IP Address": ipaddr,
                    "UDP Port": udpport,
                    "TCP Port": tcpport,
                }
        elif version in range(1, 3):
            for i in range(nodecount):
                (
                    clientid,
                    ip1,
                    ip2,
                    ip3,
                    ip4,
                    udpport,
                    tcpport,
                    typeval,
                    kadUDPkey,
                    verified,
                ) = struct.unpack("<16s4BHHBQB", nodefile.read(34))
                ipaddr = f"{ip4}.{ip3}.{ip2}.{ip1}"
                if verified == 0:
                    verif = "N"
                else:
                    verif = "Y"
                RESULT["Nodes"][i] = {
                    "Client ID": clientid.hex(),
                    "Type": typeval,
                    "IP Address": ipaddr,
                    "UDP Port": udpport,
                    "TCP Port": tcpport,
                    "KAD UDP Key": f"{kadUDPkey:x}",
                    "Verified": verif,
                }
        else:
            print(f"Unknown version: {version}!")
    return RESULT


def mulesig(sigfile):
    SIG_FIELDS = [
        "status",
        "server_name",
        "server_ip",
        "server_port",
        "id_type",
        "kad_status",
        "down_speed",
        "up_speed",
        "upload_queue",
        "shared_files",
        "user_nickname",
        "total_bytes_down",
        "total_bytes_up",
        "amule_version",
        "curr_bytes_down",
        "curr_bytes_up",
        "runtime_secs",
    ]
    SIG_VALS = []
    open_sigfile = open(sigfile, "r")
    read_sigfile = open_sigfile.readlines()
    for line in read_sigfile:
        SIG_VALS.append(line.rstrip())
    SIG_DICT = dict(zip(SIG_FIELDS, SIG_VALS))
    return SIG_DICT


def addresses(address_dat):
    ADDR_LIST = {}
    with open(address_dat, "r") as addr_content:
        addrs = addr_content.readlines()
        for address in addrs:
            ADDR_LIST[addrs.index(address)] = address.rstrip()
    return ADDR_LIST


def canceled(canceled_met):
    CANCELED_HASHES = {}
    
    open_canceled = open(canceled_met, "rb")
    integrity_byte = open_canceled.read(1)
    if integrity_byte.decode() == "!":
        pass
    else:
        print("File is not a valid canceled.met file - invalid signature")
        return None, None
    num_hash_bytes = open_canceled.read(4)
    num_hashes = struct.unpack("<I", num_hash_bytes)[0]
    CANCELED_HASHES['Number of Hashes'] = num_hashes
    CANCELED_HASHES['Hashes'] = {}
    for i in range(num_hashes):
        hash_bytes = open_canceled.read(16)
        hash_val = hash_bytes.hex()
        CANCELED_HASHES['Hashes'][i] = hash_val
    return CANCELED_HASHES


def main():
    ver = f"%(prog)s v{str(__version__)}"
    arg_parse = ArgumentParser(description="eMule/aMule file parser")
    arg_parse.add_argument("-d", "--dir", help="directory containing xMule files")
    arg_parse.add_argument("-f", "--file", help="single file to process")
    arg_parse.add_argument("-o", "--output", help="path to file for output")
    arg_parse.add_argument("-v", action="version", version=ver)
    args = arg_parse.parse_args()
    if len(sys.argv[1:]) == 0:
        arg_parse.print_help()
        arg_parse.exit()
    if args.file and args.dir:
        print(
            "[!] Only one of 'file' or 'dir' is required, but not both. "
            "Please try your command again",
            file=sys.stderr,
        )
        raise SystemExit(1)
    output = process(args.dir, args.file)
    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write(str(output))
    else:
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
