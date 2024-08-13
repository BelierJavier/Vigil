import boto3
import json
from datetime import datetime, timedelta

# Initialize session
logs_client = boto3.client('logs')

def parse_log(message):
    try:
        protocol, srcaddr, dstaddr, srcport, dstport, packets, byts, tcp_flags = message.split()
        return {
            'protocol': protocol,
            'srcaddr': srcaddr,
            'dstaddr': dstaddr,
            'srcport': int(srcport),
            'dstport': int(dstport),
            'packets': int(packets),
            'bytes': int(byts),
            'tcp-flags': int(tcp_flags)
        }
    
    except ValueError as e:
        print(f"Failed to parse message: {message}")
        return None


def collect_vpc_logs(log_group, log_stream, start_time, end_time):
    try: 
        response = logs_client.filter_log_events(
            logGroupName = log_group,
            logStreamNames = [log_stream],
            startTime = start_time,
            endTime = end_time
            )

    except logs_client.exceptions.ResourceNotFoundException:
        print(f"Log group {log_group} or log stream {log_stream} does not exist.")
        return [] 

    logs = []
    for event in response['events']:
        message = event['message']
        log_event = parse_log(message)
        if log_event:
            logs.append(log_event)

    return logs


if __name__ == "__main__":

    log_group = 'vpc-network-records'
    log_stream = 'eni-0387ec7084bd2bb47-all'
    start_time = int((datetime.now() - timedelta(minutes=10)).timestamp() * 1000) # 10 minutes ago
    end_time = int(datetime.now().timestamp() * 1000) # Current time
    logs = collect_vpc_logs(log_group, log_stream, start_time, end_time)

    if logs:
        with open('data_dump/vpc_logs.json', 'w') as f:
            json.dump(logs, f)
    else:
        print("No logs collected.")

