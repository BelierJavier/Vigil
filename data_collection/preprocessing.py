import pandas as pd
import numpy as np
import json
import pickle

def infer_service_from_port(port):
    port_enc_mapping = {
    0: 46, # private
    5: 49, # rje
    7: 12, # echo
    9: 9, # discard
    11: 56, # systat
    13: 8, # daytime
    15: 37, # netstat
    20: 19, # ftp_data   
    21: 18, # ftp
    22: 53, # ssh
    23: 57, # telnet
    25: 51, # smtp
    37: 59, # time
    42: 33, # name
    43: 65, # whois
    53: 10, # domain
    57: 32, # mpt
    66: 52, # sql_net
    70: 20, # gopher
    79: 17, # finger
    80: 22, # http
    84: 7, # ctf
    87: 30, # link
    91: 48, # remote_job
    92: 14, # ecr_i
    95: 55, # supdup
    101: 21, # hostnames
    102: 26, # iso_tsap
    105: 6, # csnet_ns
    109: 43, # pop2
    110: 44, # pop3
    111: 54, # sunrpc
    113: 3, # auth
    115: 13, # eco_i
    117: 63, # uucp_path
    119: 39, # nntp
    123: 40, # ntp_u
    137: 35, # netbios_ns
    138: 34, # netbios_dgm
    139: 36, # netbios_ssn
    143: 25, # imap
    175: 64, # vmnet
    179: 4, # bgp
    210: 2, # z39_50
    389: 29, # ldap
    433: 38, # nnsp
    443: 23, # https
    512: 16, # exec
    513: 31, # login
    514: 50, # shell
    515: 45, # printer
    520: 15, # efs
    522: 61, # urp_i
    540: 62, # uucp
    543: 27, # klogin
    544: 28, # kshell
    555: 60, # urh_i
    653: 58, # tim_i
    711: 42, # pm_dump
    932: 47, # red_i
    989: 67, # ftps_data
    990: 66, # ftps
    993: 68, # imaps
    995: 69, # pop3s
    6000: 1, # x11
    8001: 24 # http_8001
    }

    # Infer service from the port number
    return port_enc_mapping.get(port, 46)

def decode_tcp_flags(tcp_flag_value): 
    flags = []
    if tcp_flag_value & 1:
        flags.append('FIN')
    if tcp_flag_value & 2:
        flags.append('SYN')
    if tcp_flag_value & 4:
        flags.append('RST')
    if tcp_flag_value & 8:
        flags.append('PSH')
    if tcp_flag_value & 16:
        flags.append('ACK')
    if tcp_flag_value & 32:
        flags.append('URG')
    return flags


def convert_to_high_level_flag(tcp_flag_value):
    tcp_flags = decode_tcp_flags(tcp_flag_value)
    
    if 'RST' in tcp_flags:
        if 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
            return 'SH'  # Connection attempted with SYN, but reset immediately by client (10)
        elif 'SYN' in tcp_flags and 'ACK' in tcp_flags:
            return 'RSTO'  # Connection reset after data sent (2)
        elif 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
            return 'RSTOS0'  # SYN sent, no SYN-ACK received, then connection reset (3)
        elif 'SYN' not in tcp_flags and 'ACK' in tcp_flags:
            return 'REJ'  # Connection rejected (1)
        else:
            return 'RSTR'  # Connection reset during data transfer (4)
    elif 'SYN' in tcp_flags and 'FIN' in tcp_flags:
        return 'SF'  # Successful connection with data transfer (9)
    elif 'SYN' in tcp_flags and 'ACK' not in tcp_flags:
        return 'S0'  # Connection attempt seen, no reply (5)
    elif 'SYN' in tcp_flags and 'ACK' in tcp_flags and 'FIN' not in tcp_flags:
        return 'S1'  # Connection established, no data sent (6)
    elif 'ACK' in tcp_flags and 'FIN' not in tcp_flags:
        return 'S2'  # Connection established, incomplete data transfer (7)
    elif 'FIN' in tcp_flags and not any(flag in tcp_flags for flag in ['SYN', 'RST']):
        return 'S3'  # Connection established, incomplete, no data (8)
    else:
        return 'OTH'  # Other connection states (0)


def preprocess_flow_logs(logs, scaler):
    # Mapping protocol numbers to protocol strings
    protocol_mapping = {'6': 'tcp', '17': 'udp', '1': 'icmp'}
    protocol_enc_mapping = {'tcp': 1, 'udp': 2, 'icmp': 3, 'other': 4 }
    flag_enc_mapping = {'OTH': 0, 'REJ': 1, 'RSTO': 2, 'RSTOS0': 3, 'RSTR': 4, 'S0': 5, 'S1': 6, 'S2': 7, 'S3': 8, 'SF': 9, 'SH':10}

    # Transforming logs into dataframes
    parsed_logs = []
    for log in logs:
        protocol_type = protocol_mapping.get(log.get('protocol'), 'other')
        encoded_protocol = protocol_enc_mapping.get(protocol_type, 4)

        high_level_flag = convert_to_high_level_flag(log.get('tcp_flags', 0))
        encoded_flag = flag_enc_mapping.get(high_level_flag, 0)

        parsed_log = {
            'protocol_type': encoded_protocol,
            'src_bytes': log.get('bytes', 0),
            'dst_bytes': log.get('bytes', 0),
            'packets': log.get('packets', 0),
            'flag': encoded_flag,
            'srcaddr': log.get('srcaddr'),
            'dstaddr': log.get('dstaddr'),
            'srcport': log.get('srcport', 0),
            'dstport': log.get('dstport', 0),
        }
        parsed_logs.append(parsed_log)

    df = pd.DataFrame(parsed_logs)

    # Compute additional selected features for model prediction 
    df['service'] = df['dstport'].apply(infer_service_from_port)
    df['count'] = df.groupby('dstaddr')['srcaddr'].transform('count')
    df['same_srv_rate'] = (df.groupby(['dstaddr', 'dstport'])['dstport'].transform('count') / df['count']).round(2)
    df['diff_srv_rate'] = (1 - df['same_srv_rate']).round(2)
    df['dst_host_srv_count'] = df.groupby(['dstaddr', 'dstport'])['dstport'].transform('count')
    df['dst_host_same_srv_rate'] = (df['dst_host_srv_count'] / df['count']).round(2)

    # Drop columns not needed for model
    df = df.drop(columns=['srcaddr', 'dstaddr', 'srcport', 'dstport'])

    # Convert DataFrame to numpy array to remove feature names before scaling
    df_values = df.values

    # Ensure all features are numeric
    df = df.apply(pd.to_numeric, errors='coerce')

    desired_order = [
        'protocol_type',
        'service',
        'flag',
        'src_bytes',
        'dst_bytes',
        'count',
        'same_srv_rate',
        'diff_srv_rate',
        'dst_host_srv_count',
        'dst_host_same_srv_rate'
    ]

    # Reorder the DataFrame according to the desired order
    df = df[desired_order]
    
    # Scale the data using the provided scaler
    scaled_data = scaler.transform(df.values)

    # Convert the scaled data to scientific notation and to a Python list
    #formatted_data = [[f'{num:.8e}' for num in row] for row in scaled_data.tolist()]

    return scaled_data.tolist()


def save_preprocessed_data(data, output_file):
    # Save the preprocessed data to a file in the required format
    with open(output_file, 'w') as f:
        json.dump(data, f)


def mainPreprocessing():
    # Load logs
    with open('data_dump/vpc_logs.json', 'r') as f:
        logs = json.load(f)

    # Load the scaler used during training using pickle
    with open('models/vigil_scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)

    # Preprocess logs
    preprocessed_data = preprocess_flow_logs(logs, scaler)

    # Save preprocessed data
    output_file = 'data_dump/flow_logs.json'
    save_preprocessed_data(preprocessed_data, output_file)
