from elasticsearch import Elasticsearch
from datetime import datetime
import subprocess
import logging
import os

# ---------- CONFIG ----------
ELASTIC_URL = "https://localhost:9200"
USERNAME = "elastic"
PASSWORD = "kP_bzOjkdqV-*l1wn+5W" # Use your own username / password, these are just local placeholders

# Index pattern (alerts)
INDEX = ".internal.alerts-security.alerts-default-*"

# Rule name we want to react to
RULE_NAME = ">3 Failed SSH logon attempts in 5 minutes"

# Files
BLOCKLIST_FILE = "blocked_ips.txt"
LOG_FILE = "ipblocker.log"


# ---------- LOGGING ----------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

log.info("=== ipblocker started ===")


# ---------- ELASTIC CONNECTION ----------
# verify_certs=False → works locally, but insecure (fine for localhost)
es = Elasticsearch(
    ELASTIC_URL,
    basic_auth=(USERNAME, PASSWORD),
    verify_certs=False
)


# ---------- MEMORY BLOCKLIST ----------
# We keep already blocked IPs in memory to avoid duplicates
blocked_ips = set()


# ---------- LOAD BLOCKLIST FROM FILE ----------
if os.path.exists(BLOCKLIST_FILE):
    with open(BLOCKLIST_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # support both "ip,timestamp" and "ip timestamp"
            line = line.replace(",", " ")
            parts = line.split()

            if parts:
                blocked_ips.add(parts[0])

log.info(f"Loaded {len(blocked_ips)} blocked IPs")


# ---------- SAVE IP TO FILE ----------
def save_ip(ip):
    ts = datetime.now().astimezone().isoformat()

    # append IP + timestamp
    with open(BLOCKLIST_FILE, "a") as f:
        f.write(f"{ip},{ts}\n")

    log.debug(f"Saved {ip}")


# ---------- CHECK IF IP ALREADY BLOCKED IN UFW ----------
def ip_already_blocked(ip):
    output = subprocess.check_output(["sudo", "ufw", "status"]).decode()
    return ip in output


# ---------- FIND POSITION OF SSH ALLOW RULE ----------
# We insert BEFORE the allow rule so deny has priority
def find_ssh_allow_rule():
    output = subprocess.check_output(
        ["sudo", "ufw", "status", "numbered"]
    ).decode()

    for line in output.splitlines():
        if "22" in line and "ALLOW IN" in line:
            return line.split("]")[0].replace("[", "").strip()

    # fallback if not found
    return "3"


# ---------- BLOCK IP ----------
def block_ip(ip):
    # skip if already blocked in firewall
    if ip_already_blocked(ip):
        log.info(f"[=] Already blocked {ip}")
        return True

    rule_pos = find_ssh_allow_rule()

    # insert deny rule BEFORE ssh allow
    result = subprocess.run([
        "sudo", "ufw", "insert", rule_pos,
        "deny", "from", ip, "to", "any", "port", "22"
    ], capture_output=True, text=True)

    if result.returncode == 0:
        log.info(f"[+] Blocked {ip}")
        return True
    else:
        log.error(f"[!] Block FAILED {ip}: {result.stderr}")
        return False


# ---------- CLOSE ALERT IN ELASTIC ----------
def close_alert(hit):
    alert_id = hit["_id"]

    # IMPORTANT: must use real index (no wildcard!)
    index = hit["_index"]

    try:
        es.update(
            index=index,
            id=alert_id,
            doc={
                "kibana.alert.workflow_status": "closed"
            }
        )
        log.info(f"[✓] Closed alert {alert_id} in index {index}")

    except Exception as e:
        log.error(f"[!] Failed to close alert {alert_id}: {e}")


# ---------- EXTRACT IP ----------
# Some logs store it differently → handle both cases
def get_ip(source):
    ip = source.get("source", {}).get("ip")
    if ip:
        return ip

    return source.get("source.ip")


# ---------- SEARCH ALERTS ----------
log.info("Searching alerts...")

resp = es.search(
    index=INDEX,
    size=100,  # ⚠️ only latest 100 alerts
    sort=[{"@timestamp": {"order": "desc"}}],
    query={
        "bool": {
            "must": [
                {"match_phrase": {"kibana.alert.rule.name": RULE_NAME}},
                {
                    # only recent alerts (prevents reprocessing old ones)
                    "range": {
                        "@timestamp": {
                            "gte": "now-10m" #You can set how far the script looks back for alerts - usually you should set this to the time you set your cronjob / service to run at - maybe add a small buffer.
                        }
                    }
                }
            ]
        }
    }
)

log.info(f"Found {resp['hits']['total']['value']} hits")


new_blocks = 0
skipped = 0


# ---------- PROCESS ALERTS ----------
for i, hit in enumerate(resp["hits"]["hits"]):
    source = hit["_source"]
    doc_id = hit["_id"]
    timestamp = source.get("@timestamp", "N/A")

    log.info(f"--- Hit {i+1} ---")
    log.info(f"ID: {doc_id}")
    log.info(f"Time: {timestamp}")

    ip = get_ip(source)

    if not ip:
        log.warning("No IP found")
        skipped += 1
        continue

    log.info(f"IP: {ip}")

    # extra debug info
    event_action = source.get("event", {}).get("action", "N/A")
    reason = source.get("kibana", {}).get("alert", {}).get("reason", "N/A")

    # IMPORTANT: check alert status
    status = source.get("kibana", {}).get("alert", {}).get("workflow_status")

    log.debug(f"Action: {event_action}")
    log.debug(f"Reason: {reason}")

    # ---------- SKIP IF ALREADY CLOSED ----------
    if status == "closed":
        log.debug(f"Already closed: {doc_id}")
        skipped += 1
        continue

    # ---------- CASE 1: already blocked ----------
    if ip in blocked_ips:
        log.info(f"[~] Already in blocklist {ip}")

        # still close alert even if already blocked
        close_alert(hit)

        skipped += 1
        continue

    # ---------- CASE 2: block new attacker ----------
    success = block_ip(ip)

    if success:
        blocked_ips.add(ip)
        save_ip(ip)

        # close alert after successful block
        close_alert(hit)

        new_blocks += 1
    else:
        log.warning(f"[!] Not closing alert because block failed for {ip}")


log.info(f"Done. New: {new_blocks}, Skipped: {skipped}")


# ---------- SAVE LAST RUN ----------
with open("last_run.txt", "w") as f:
    f.write(datetime.now().astimezone().isoformat())

log.info("=== ipblocker finished ===")
