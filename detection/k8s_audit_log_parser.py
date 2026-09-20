import sys
import json
from typing import List, Dict

def analyze_k8s_audit_logs(log_file_path: str) -> List[Dict]:
    threats = []
    
    with open(log_file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            try:
                log_entry = json.loads(line)
                
                # Detect unauthorized access attempts
                response_status = log_entry.get('responseStatus', {})
                if response_status.get('code') in [401, 403]:
                    user = log_entry.get('user', {}).get('username', 'unknown')
                    verb = log_entry.get('verb', 'unknown')
                    resource = log_entry.get('objectRef', {}).get('resource', 'unknown')
                    
                    threats.append({
                        'type': 'Unauthorized Access Attempt',
                        'user': user,
                        'action': f"{verb} on {resource}",
                        'code': response_status.get('code'),
                        'raw_log': log_entry
                    })
                    
                # Detect execution into a pod (kubectl exec)
                if log_entry.get('verb') == 'create' and log_entry.get('objectRef', {}).get('subresource') == 'exec':
                    user = log_entry.get('user', {}).get('username', 'unknown')
                    namespace = log_entry.get('objectRef', {}).get('namespace', 'unknown')
                    pod = log_entry.get('objectRef', {}).get('name', 'unknown')
                    
                    threats.append({
                        'type': 'Pod Execution (kubectl exec)',
                        'user': user,
                        'target': f"pod/{pod} in namespace {namespace}",
                        'raw_log': log_entry
                    })
                    
            except json.JSONDecodeError:
                print(f"Warning: Could not parse JSON log line: {line}")
                
    return threats

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python k8s_audit_log_parser.py <path_to_audit_log_jsonl>")
        sys.exit(1)
        
    log_file = sys.argv[1]
    detected_threats = analyze_k8s_audit_logs(log_file)
    
    print(f"Analysis complete for {log_file}. Found {len(detected_threats)} notable events.")
    for t in detected_threats:
        if t['type'] == 'Unauthorized Access Attempt':
            print(f"[!] {t['type']}: User '{t['user']}' attempted '{t['action']}' but received {t['code']}.")
        elif t['type'] == 'Pod Execution (kubectl exec)':
            print(f"[*] {t['type']}: User '{t['user']}' executed command in {t['target']}.")
