from elasticsearch import Elasticsearch
from datetime import datetime
import subprocess
import os
# My URL and credentials are just placeholders, use yours instead!
ELASTIC_URL = "https://localhost:9200" 
USERNAME = "elastic"
PASSWORD = "kP_bzOjkdqV-*l1wn+5W"

INDEX = ".internal.alerts-security.alerts-default-*"
RULE_NAME = ">3 Failed SSH logon attempts in 5 minutes"

BLOCKLIST_FILE = "blocked_ips.txt"

es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(USERNAME, PASSWORD),
    verify_certs=False
)

blocked_ips = set()

# ---------- BLOCKLIST LADEN ----------
if os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            line = line.replace(",", " ")
            parts = line.split()

            if parts:
                blocked_ips.add(parts[0])

print(f"Loaded {len(blocked_ips)} blocked IPs")

# ---------- IP SPEICHERN ----------
def save_ip(ip):
    ts = datetime.now().astimezone().isoformat()
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(f"{ip},{ts}\n")

# ---------- UFW CHECK ----------
def ip_already_blocked(ip):
    output = subprocess.check_output(
        ["sudo", "ufw", "status"]
    ).decode()
    return ip in output

# ---------- SSH RULE POSITION ----------
def find_ssh_allow_rule():
    output = subprocess.check_output(
        ["sudo", "ufw", "status", "numbered"]
    ).decode()

    for line in output.splitlines():
        if "22" in line and "ALLOW IN" in line:
            num = line.split("]")[0].replace("[", "").strip()
            return num

    return "3"

# ---------- BLOCK ----------
def block_ip(ip):
    if ip_already_blocked(ip):
        print(f"[=] Already blocked {ip}")
        return

    rule_pos = find_ssh_allow_rule()

    subprocess.run([
        "sudo", "ufw", "insert", rule_pos,
        "deny", "from", ip, "to", "any", "port", "22"
    ])

    print(f"[+] Blocking {ip}")

# ---------- ELASTIC SEARCH ----------
print("Searching alerts...")

resp = es.search(
    index=INDEX,
    size=50,
    query={
        "bool": {
            "must": [
                {"match_phrase": {"kibana.alert.rule.name": RULE_NAME}}
            ]
        }
    }
)

for hit in resp["hits"]["hits"]:
    ip = hit["_source"].get("source", {}).get("ip")

    if not ip:
        continue

    if ip in blocked_ips:
        continue

    block_ip(ip)
    blocked_ips.add(ip)
    save_ip(ip)

# ---------- LAST RUN SPEICHERN ----------
with open("last_run.txt", "w") as f:
    f.write(datetime.now().astimezone().isoformat())
