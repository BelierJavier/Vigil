### MAC VERSION ###

# IMPORT LIBRARIES
#import pickle
import socket
import struct
#import textwrap

#knn_loaded = pickle.load('ids_model','rb')

def sniff(interface):
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((interface, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    
    try:
        while True:
            print("Currently Scanning")
            raw_packet = sniffer.recvfrom(65565)
            dest_ip, src_ip, proto, data = unpack_frame(raw_packet[0])
            print(f"Source IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {proto}")
            print(f"Data: {data}")

    except KeyboardInterrupt:
        print("Packet Capture Stopped")

def unpack_frame(raw_packet):
    header_length = (raw_packet[0] & 15) * 4
    dest_ip, src_ip, proto = struct.unpack('! 4s 4s B', raw_packet[16:28])
    data = raw_packet[header_length:]
    return socket.inet_ntoa(dest_ip), socket.inet_ntoa(src_ip), proto, data

if __name__ == "__main__" :
    interface = "en0"
    sniff(interface)