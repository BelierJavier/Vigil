### LINUX VERSION ###

# IMPORT LIBRARIES
import pickle
import socket
import struct
import numpy as np
import pandas as pd
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '


def IDS(packet):
    with open('ids_model', 'rb') as f:
        knnIDS = pickle.load(f)
    unit = np.array([1,80244,2,0,12,0,6,6,6.0,0.0,0,0,0.0,0.0,149.543891,24.923982,80244.0,0.0,80244,80244,80244.0,0.0,80244,80244,0,0.0,0.0,0,0,0,0,0,0,40,0,24.923982,0.0,6,6,6.0,0.0,0.0,0,9.0,6.0,0.0,0,0,0,0,0,0,2,12,0,0,255,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0])
    packetdf = pd.DataFrame(packet).transpose()
    print(knnIDS.predict(packetdf))

def sniff():
    TCP_conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    network_streams = []

    try:
        print('Scanning')
        i = 0
        while True:
            raw_data, addr = TCP_conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack_frame(raw_data)
            print(ipv4_packet(data))
            (version, header_length, ttl, proto, src, target, data ) = ipv4_packet(data)
            print('\nEthernet Frame:')
            print('{} : TCP | Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(i, dest_mac, src_mac, eth_proto))
            print(TAB_1 + 'Destination IP: {}, Source IP: {}, TTL: {}'.format(target, src, ttl))
            i += 1
        
            try:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                capture_flow(src_port, dest_port, flag_syn, flag_ack, flag_rst, flag_fin)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags: ')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))
            
            except struct.error:
                print('Struct Error Occurred: Not a TCP Packet')
    
    except KeyboardInterrupt:
        print('Packet Capture Stopped')

    def capture_flow(src, dest, syn, ack, rst, fin ):
        pass

# UNPACK ETHERNET FRAME
def unpack_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # Unpacking first 14 bytes (DEST, SOURCE, PROTOCOL)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] # Returning data after 14 bytes (PAYLOAD)

# RETURN MAC ADDRESS INTO READABLE FORMAT (ex. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) # Takes all chunks & formats them properly to 2 decimal places
    return ':'.join(bytes_str).upper() # Joins formatted chunks together to form MAC addr with ':'

# UNPACK IPV4 PACKET
def ipv4_packet(data):
    version_header_length = data[0] # Reads version header length
    version = version_header_length >> 4 # Reads Version by shifting 4 bytes to right from version header length
    header_length = (version_header_length & 15) * 4 # Reads entire header length
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) # Unpacks header data
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:] # Returning header data

# RETURNING IP ADDRESS INTO READABLE FORMAT (ex. 127.0.0.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

# UNPACKIN TCP PACKETS
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 5
    flag_psh = (offset_reserved_flags & 8) >> 5
    flag_rst = (offset_reserved_flags & 4) >> 5
    flag_syn = (offset_reserved_flags & 2) >> 5
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# UNPACKING ICMP PACKETS
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# FORMATTING LONG LINES OF DATA FOR BETTER VISUALIZATION
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])



if __name__ == "__main__":
    IDS()

