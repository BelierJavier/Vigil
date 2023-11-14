### LINUX VERSION ###

# IMPORT LIBRARIES
#import pickle
import socket
import struct
#import textwrap

#knn_loaded = pickle.load('ids_model','rb')

class Stream():
    pass

def sniff():
    TCP_conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    try:
        print('Scanning')
        i = 0
        while True:
            raw_data, addr = TCP_conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack_frame(raw_data)
            print('\nEthernet Frame:')
            print('{} : TCP | Destination: {}, Source: {}, Protocol: {}'.format(i, dest_mac, src_mac, eth_proto))
            i += 1
    
    except KeyboardInterrupt:
        print('Packet Capture Stopped')

# UNPACK ETHERNET FRAME
def unpack_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # Unpacking first 14 bytes (DEST, SOURCE, PROTOCOL)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] # Returning data after 14 bytes (PAYLOAD)

# RETURN MAC ADDRESS INTO READABLE FORMAT (ex. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) # Takes all chunks & formats them properly to 2 decimal places
    return ':'.join(bytes_str).upper() # Joins formatted chunks together to form MAC addr with ':'

if __name__ == "__main__":
    sniff()

