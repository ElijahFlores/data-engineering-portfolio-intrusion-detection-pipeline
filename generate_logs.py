"""
Generate realistic SSH authentication logs with security anomalies
Fixed: Space-padded days, realistic usernames, year boundary handling
"""
import random
import os
from datetime import datetime, timedelta

def generate_sample_logs(filename='ssh_auth.log', num_entries=5000, output_dir='data/raw'):
    """
    Generates sample SSH authentication logs with:
    - Normal user activity
    - Brute force attack patterns
    - Suspicious geographic access
    - Failed login attempts
    
    Args:
        filename: Output log filename
        num_entries: Number of log entries to generate
        output_dir: Output directory path
    """
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Realistic IP pools
    normal_ips = [
        '192.168.1.10', '192.168.1.15', '192.168.1.20',
        '10.0.0.5', '10.0.0.8', '172.16.0.100', '172.20.1.50'
    ]
    
    # Attacker IPs (will show brute force pattern)
    attacker_ips = [
        '45.142.212.61',  # Russia
        '103.75.201.12',  # China
        '185.220.101.45', # Tor exit node
    ]
    
    # Suspicious country IPs
    suspicious_ips = [
        '91.108.56.190',  # Kazakhstan
        '196.201.233.45', # Nigeria
        '41.60.232.191',  # Kenya
    ]
    
    # FIXED: Usernames without special characters for regex compatibility
    normal_users = ['admin', 'johndoe', 'janesmith', 'devops', 'support', 'backup']
    common_attack_users = ['root', 'admin', 'user', 'test', 'oracle', 'postgres', 'mysql']
    
    base_time = datetime.now() - timedelta(days=7)
    
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        for i in range(num_entries):
            timestamp = base_time + timedelta(seconds=i*10 + random.randint(0, 30))
            
            # Decide event type
            event_type = random.choices(
                ['normal', 'brute_force', 'suspicious_geo', 'failed_normal'],
                weights=[70, 15, 10, 5]
            )[0]
            
            if event_type == 'normal':
                ip = random.choice(normal_ips)
                user = random.choice(normal_users)
                status = random.choices(['Accepted', 'Failed'], weights=[95, 5])[0]
                
            elif event_type == 'brute_force':
                ip = random.choice(attacker_ips)
                user = random.choice(common_attack_users)
                status = 'Failed'  # Brute force attempts usually fail
                
            elif event_type == 'suspicious_geo':
                ip = random.choice(suspicious_ips)
                user = random.choice(normal_users + common_attack_users)
                status = random.choices(['Failed', 'Accepted'], weights=[80, 20])[0]
                
            else:  # failed_normal
                ip = random.choice(normal_ips)
                user = random.choice(normal_users)
                status = 'Failed'
            
            # FIXED: Space-padded day format (e.g., "Jan  1" not "Jan 01")
            month = timestamp.strftime('%b')
            day = timestamp.strftime('%d').lstrip('0').rjust(2)  # Space-padded
            time = timestamp.strftime('%H:%M:%S')
            
            if status == 'Accepted':
                log_line = f"{month} {day} {time} server sshd[{random.randint(1000, 9999)}]: Accepted password for {user} from {ip} port {random.randint(40000, 60000)} ssh2\n"
            else:
                log_line = f"{month} {day} {time} server sshd[{random.randint(1000, 9999)}]: Failed password for {user} from {ip} port {random.randint(40000, 60000)} ssh2\n"
            
            f.write(log_line)
    
    print(f"✓ Generated {num_entries} log entries in {filepath}")
    print(f"  - Normal activity: ~70%")
    print(f"  - Brute force patterns: ~15%")
    print(f"  - Suspicious geographic access: ~10%")
    print(f"  - Failed normal logins: ~5%")
    print(f"\nSample entries:")
    
    # Show samples
    with open(filepath, 'r') as f:
        lines = f.readlines()
        for i in [0, len(lines)//2, -1]:
            print(f"  {lines[i].strip()}")

if __name__ == "__main__":
    generate_sample_logs()
