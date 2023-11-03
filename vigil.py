# IMPORT LIBRARIES
import pickle
import socket
import struct
#import textwrap

#knn_loaded = pickle.load('ids_model','rb')

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


# UNPACK ETHERNET FRAME
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) # Unpacking first 14 bytes (DEST, SOURCE, PROTOCOL)
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] # Returning data after 14 bytes (PAYLOAD)

# RETURN MAC ADDRESS INTO READABLE FORMAT (ex. AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr) # Takes all chunks & formats them properly to 2 decimal places
    return ':'.join(bytes_str).upper() # Joins formatted chunks together to form MAC addr with ':'

main()

