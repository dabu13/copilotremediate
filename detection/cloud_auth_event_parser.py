import sys
import json
from typing import List, Dict

def analyze_cloud_auth_events(log_file_path: str) -> List[Dict]:
    anomalies = []
    
    with open(log_file_path, 'r') as f:
        # Assuming AWS CloudTrail format in JSON for this example
        try:
            data = json.load(f)
            records = data.get('Records', [])
        except json.JSONDecodeError:
            print(f"Error reading JSON from {log_file_path}")
            return anomalies
            
        for event in records:
            event_name = event.get('eventName')
            event_source = event.get('eventSource')
            
            # Focus on ConsoleLogin events
            if event_name == 'ConsoleLogin' and event_source == 'signin.amazonaws.com':
                response_elements = event.get('responseElements', {})
                
                # Check for login failures
                if response_elements.get('ConsoleLogin') == 'Failure':
                    anomalies.append({
                        'type': 'Failed Console Login',
                        'user': event.get('userIdentity', {}).get('userName', 'unknown'),
                        'source_ip': event.get('sourceIPAddress', 'unknown'),
                        'time': event.get('eventTime')
                    })
                
                # Check for successful logins WITHOUT MFA
                elif response_elements.get('ConsoleLogin') == 'Success':
                    additional_info = event.get('additionalEventData', {})
                    if additional_info.get('MFAUsed') != 'Yes':
                        anomalies.append({
                            'type': 'Login without MFA',
                            'user': event.get('userIdentity', {}).get('userName', 'unknown'),
                            'source_ip': event.get('sourceIPAddress', 'unknown'),
                            'time': event.get('eventTime')
                        })
                        
    return anomalies

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cloud_auth_event_parser.py <path_to_cloudtrail_json>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    detected_anomalies = analyze_cloud_auth_events(log_file)
    
    print(f"Analysis complete for {log_file}. Found {len(detected_anomalies)} authentication anomalies.")
    for anomaly in detected_anomalies:
        print(f"[!] {anomaly['type']} | User: {anomaly['user']} | IP: {anomaly['source_ip']} | Time: {anomaly['time']}")
