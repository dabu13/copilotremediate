import sys
import csv
from typing import List, Dict

# AWS VPC Flow Log default format:
# version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
# Example: 2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 REJECT OK

def parse_vpc_flow_logs(log_file_path: str) -> List[Dict]:
    threats_detected = []
    
    with open(log_file_path, 'r') as f:
        # Assuming space-separated values
        reader = csv.reader(f, delimiter=' ')
        for row in reader:
            if not row or row[0] == 'version':
                continue
                
            try:
                log_entry = {
                    'version': row[0],
                    'account_id': row[1],
                    'interface_id': row[2],
                    'srcaddr': row[3],
                    'dstaddr': row[4],
                    'srcport': row[5],
                    'dstport': row[6],
                    'protocol': row[7],
                    'packets': row[8],
                    'bytes': row[9],
                    'start': row[10],
                    'end': row[11],
                    'action': row[12],
                    'log_status': row[13]
                }
                
                # Threat Detection Logic: Monitor for Rejected SSH (22) or RDP (3389) traffic
                if log_entry['action'] == 'REJECT':
                    if log_entry['dstport'] in ['22', '3389']:
                        threats_detected.append({
                            'type': 'Rejected Admin Port Access',
                            'source_ip': log_entry['srcaddr'],
                            'target_ip': log_entry['dstaddr'],
                            'port': log_entry['dstport'],
                            'raw_log': " ".join(row)
                        })
            except IndexError:
                print(f"Warning: Malformed log line: {' '.join(row)}")
                
    return threats_detected

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vpc_flow_log_parser.py <path_to_log_file>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    threats = parse_vpc_flow_logs(log_file)
    
    print(f"Analyzed {log_file}. Found {len(threats)} potential threats.")
    for threat in threats:
        print(f"[!] {threat['type']} from {threat['source_ip']} to {threat['target_ip']}:{threat['port']}")
# Need to get this logic tested against some sample logs to see if it works
# Terraform having a repo structure setup form before with modules might help you
# Data structures like list/dictionary and mix-match like list of dictionary or dictionary of list might be involved
