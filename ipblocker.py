from elasticsearch import Elasticsearch
from datetime import datetime
import subprocess
import os

ELASTIC_URL = "https//:#localhost:9200" #If your elasticsearch doesnt use TLS/SSL, use http instead
USERNAME = "<Username>" #Insert your elasticsearch username
PASSWORD = "<Password>" #Insert your elasticsearch password

INDEX = ".internal.alerts-security.alerts-default-*"  #This is the default index for alerts, make sure its the right one on your elasticsearch tho
RULE_NAME = ">3 Failed SSH logon attempts in 5 minutes" #This wont work for you -> Its a custom rule so make sure you either create a rule with the same name or use a different Rule

BLOCKLIST_FILE = "blocked_ips.txt"

es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(USERNAME, PASSWORD),
    verify_certs=False #This is to not verify SSL/TLS Certificates, which is insecure but okay for a homelab. Please remove this line in a production environment.
)

blocked_ips = set()

# ---------- LOAD BLOCKLIST ----------
if os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ip = line.split(",")[0].split()[0]
            blocked_ips.add(ip)

# ---------- SAVE IP ----------
def save_ip(ip):
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(f"{ip} {datetime.now().astimezone().isoformat()}\n")

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
