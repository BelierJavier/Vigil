### MAC VERSION ###

# IMPORT LIBRARIES
#import pickle
import socket
import struct
#import textwrap

#knn_loaded = pickle.load('ids_model','rb')

def sniff():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((interface, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

def unpack_frame(raw_packet):
    header_length = (raw_packet[0] & 15) * 4
    dest_ip, src_ip, proto = struct.unpack('! 4s 4s B', raw_packet[16:28])
    data = raw_packet[header_length:]
    return socket.inet_ntoa(dest_ip), socket.inet_ntoa(src_ip), proto, data

if __name__ == "__main__" :
    interface = "lo0"
    sniff(interface)