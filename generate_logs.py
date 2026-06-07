"""
generate_logs.py
================
Generates realistic security log files for testing the SOC Threat Detection System.

Simulates real-world attack scenarios:
  - SSH brute force attacks
  - Port scanning
  - Credential stuffing
  - After-hours logins
  - Normal legitimate traffic (to make it realistic)

Usage:
  python generate_logs.py

Output:
  sample_logs/generated_auth.log      (auth log - 2000 lines)
  sample_logs/generated_firewall.log  (firewall log - 1500 lines)
  sample_logs/generated_web.log       (web server log - 500 lines)
"""

import random
import os
from datetime import datetime, timedelta

# ── Configuration ────────────────────────────────────────────────────────────
TOTAL_AUTH_LINES      = 2000
TOTAL_FIREWALL_LINES  = 1500
TOTAL_WEB_LINES       = 500
OUTPUT_DIR            = "sample_logs"

# ── Realistic data pools ─────────────────────────────────────────────────────
ATTACKER_IPS = [
    "203.0.113.10", "203.0.113.45", "198.51.100.77",
    "192.0.2.100",  "45.33.32.156", "89.248.167.131",
    "185.220.101.5","193.32.160.43","91.108.4.22",
    "178.128.23.44"
]

LEGITIMATE_IPS = [
    "10.0.0.5",  "10.0.0.8",  "10.0.0.12",
    "10.0.0.15", "10.0.0.20", "172.16.0.5",
    "172.16.0.8","192.168.1.5","192.168.1.10"
]

USERNAMES = [
    "root", "admin", "ubuntu", "deploy", "git",
    "jenkins", "postgres", "mysql", "oracle", "user1"
]

LEGITIMATE_USERS = [
    "prasanna", "jsmith", "deploy", "admin_ops",
    "backup_user", "monitor", "devops"
]

SERVERS = ["srv-01", "srv-02", "web-01", "db-01", "app-01"]

WEB_PATHS = [
    "/", "/index.html", "/dashboard", "/login",
    "/admin", "/api/v1/users", "/admin/login",
    "/.env", "/wp-admin", "/phpmyadmin",
    "/etc/passwd", "/api/v1/data", "/logout",
    "/static/main.css", "/favicon.ico"
]

# ── Helper functions ──────────────────────────────────────────────────────────

def random_time(base_date, hour_start=0, hour_end=23):
    """Generate a random datetime within a given hour range."""
    hour   = random.randint(hour_start, hour_end)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base_date.replace(hour=hour, minute=minute, second=second)


def format_auth_time(dt):
    """Format datetime as Linux auth log timestamp: Jun  3 02:10:01"""
    day_str = f"{dt.day:2d}"
    return f"{dt.strftime(chr(37)+'b')} {day_str} {dt.strftime(chr(37)+'H:'+chr(37)+'M:'+chr(37)+'S')}"


def auth_failed(dt, ip, username, server):
    ts = format_auth_time(dt)
    pid = random.randint(1000, 9999)
    return f"{ts} {server} sshd[{pid}]: Failed password for {username} from {ip} port 22 ssh2"


def auth_success(dt, ip, username, server):
    ts = format_auth_time(dt)
    pid = random.randint(1000, 9999)
    return f"{ts} {server} sshd[{pid}]: Accepted password for {username} from {ip} port 22 ssh2"


def auth_invalid(dt, ip, username, server):
    ts = format_auth_time(dt)
    pid = random.randint(1000, 9999)
    return f"{ts} {server} sshd[{pid}]: Invalid user {username} from {ip} port 22 ssh2"


def firewall_line(dt, verdict, protocol, src_ip, dst_ip, port):
    ts = dt.strftime("%Y-%m-%d %H:%M:%S")
    return f"{ts} {verdict} {protocol} {src_ip} -> {dst_ip} port={port}"


def web_line(dt, ip, method, path, status, size):
    ts = dt.strftime("%d/%b/%Y:%H:%M:%S +1000")
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size}'


# ── Scenario generators ───────────────────────────────────────────────────────

def scenario_brute_force(base_dt, lines):
    """Single IP hammering SSH with failed logins — triggers brute_force rule."""
    ip     = random.choice(ATTACKER_IPS)
    user   = random.choice(USERNAMES)
    server = random.choice(SERVERS)
    count  = random.randint(8, 20)
    for i in range(count):
        dt = base_dt + timedelta(seconds=i * random.randint(1, 30))
        lines.append(auth_failed(dt, ip, user, server))
    return lines


def scenario_credential_stuffing(base_dt, lines):
    """Same username attacked from multiple IPs — triggers multiple_failures rule."""
    user   = random.choice(USERNAMES)
    server = random.choice(SERVERS)
    ips    = random.sample(ATTACKER_IPS, random.randint(3, 5))
    for i, ip in enumerate(ips):
        dt = base_dt + timedelta(minutes=i * random.randint(5, 15))
        lines.append(auth_failed(dt, ip, user, server))
    return lines


def scenario_after_hours_login(base_dt, lines):
    """Successful login at unusual hours — triggers after_hours_login rule."""
    ip     = random.choice(ATTACKER_IPS + LEGITIMATE_IPS)
    user   = random.choice(LEGITIMATE_USERS)
    server = random.choice(SERVERS)
    hour   = random.choice([1, 2, 3, 4, 22, 23, 0])
    dt     = base_dt.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
    lines.append(auth_success(dt, ip, user, server))
    return lines


def scenario_normal_activity(base_dt, lines):
    """Normal legitimate logins during business hours."""
    ip     = random.choice(LEGITIMATE_IPS)
    user   = random.choice(LEGITIMATE_USERS)
    server = random.choice(SERVERS)
    hour   = random.randint(8, 17)
    dt     = base_dt.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
    lines.append(auth_success(dt, ip, user, server))
    return lines


def scenario_invalid_users(base_dt, lines):
    """Attacker trying non-existent usernames."""
    ip     = random.choice(ATTACKER_IPS)
    server = random.choice(SERVERS)
    fake_users = ["administrator", "test", "guest", "oracle", "ftpuser", "pi", "hadoop"]
    for user in random.sample(fake_users, random.randint(2, 5)):
        dt = base_dt + timedelta(seconds=random.randint(1, 60))
        lines.append(auth_invalid(dt, ip, user, server))
    return lines


def scenario_port_scan(base_dt, lines):
    """Single IP hitting many ports rapidly — triggers port_scan rule."""
    src_ip = random.choice(ATTACKER_IPS)
    dst_ip = random.choice(["10.0.0.1", "10.0.0.2", "172.16.0.1"])
    ports  = random.sample(
        [21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017],
        random.randint(10, 15)
    )
    for i, port in enumerate(ports):
        dt = base_dt + timedelta(seconds=i * random.randint(1, 10))
        lines.append(firewall_line(dt, "BLOCK", "TCP", src_ip, dst_ip, port))
    return lines


def scenario_normal_firewall(base_dt, lines):
    """Normal allowed connections."""
    src_ip = random.choice(LEGITIMATE_IPS)
    dst_ip = random.choice(["10.0.0.1", "10.0.0.2"])
    port   = random.choice([80, 443, 22, 3306])
    hour   = random.randint(8, 17)
    dt     = base_dt.replace(hour=hour, minute=random.randint(0,59))
    lines.append(firewall_line(dt, "ALLOW", "TCP", src_ip, dst_ip, port))
    return lines


def scenario_web_attack(base_dt, lines):
    """Web scanning/probing attempts."""
    ip = random.choice(ATTACKER_IPS)
    attack_paths = ["/.env", "/admin", "/wp-admin", "/phpmyadmin", "/etc/passwd", "/.git/config"]
    for path in random.sample(attack_paths, random.randint(2, 4)):
        dt     = base_dt + timedelta(seconds=random.randint(1, 60))
        status = random.choice([401, 403, 404])
        lines.append(web_line(dt, ip, "GET", path, status, random.randint(128, 512)))
    return lines


def scenario_normal_web(base_dt, lines):
    """Normal web traffic."""
    ip   = random.choice(LEGITIMATE_IPS)
    path = random.choice(["/", "/dashboard", "/static/main.css", "/favicon.ico", "/api/v1/data"])
    dt   = base_dt.replace(
        hour=random.randint(8,17),
        minute=random.randint(0,59),
        second=random.randint(0,59)
    )
    lines.append(web_line(dt, ip, "GET", path, 200, random.randint(512, 8192)))
    return lines


# ── Main generator ────────────────────────────────────────────────────────────

def generate_auth_log():
    print("Generating auth log...")
    lines  = []
    # Start from 3 days ago so timestamps are recent
    base   = datetime.now() - timedelta(days=3)

    # Attack scenarios (40% of log)
    for _ in range(int(TOTAL_AUTH_LINES * 0.15)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_brute_force(dt, lines)

    for _ in range(int(TOTAL_AUTH_LINES * 0.10)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_credential_stuffing(dt, lines)

    for _ in range(int(TOTAL_AUTH_LINES * 0.05)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_after_hours_login(dt, lines)

    for _ in range(int(TOTAL_AUTH_LINES * 0.05)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_invalid_users(dt, lines)

    # Normal activity (60% of log — makes it realistic)
    for _ in range(int(TOTAL_AUTH_LINES * 0.65)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_normal_activity(dt, lines)

    # Sort by timestamp and limit
    lines = lines[:TOTAL_AUTH_LINES]
    random.shuffle(lines)
    return lines


def generate_firewall_log():
    print("Generating firewall log...")
    lines = []
    base  = datetime.now() - timedelta(days=3)

    for _ in range(int(TOTAL_FIREWALL_LINES * 0.20)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_port_scan(dt, lines)

    for _ in range(int(TOTAL_FIREWALL_LINES * 0.80)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_normal_firewall(dt, lines)

    lines = lines[:TOTAL_FIREWALL_LINES]
    random.shuffle(lines)
    return lines


def generate_web_log():
    print("Generating web server log...")
    lines = []
    base  = datetime.now() - timedelta(days=3)

    for _ in range(int(TOTAL_WEB_LINES * 0.25)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_web_attack(dt, lines)

    for _ in range(int(TOTAL_WEB_LINES * 0.75)):
        dt = base + timedelta(minutes=random.randint(0, 4320))
        scenario_normal_web(dt, lines)

    lines = lines[:TOTAL_WEB_LINES]
    random.shuffle(lines)
    return lines


# ── Write files ───────────────────────────────────────────────────────────────

def write_log(filename, lines):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    print(f"  Written: {path} ({len(lines)} lines)")


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    auth_lines     = generate_auth_log()
    firewall_lines = generate_firewall_log()
    web_lines      = generate_web_log()

    write_log("generated_auth.log",     auth_lines)
    write_log("generated_firewall.log", firewall_lines)
    write_log("generated_web.log",      web_lines)

    total = len(auth_lines) + len(firewall_lines) + len(web_lines)
    print(f"\nDone! {total} total log lines generated across 3 files.")
    print("Now run:")
    print("  python manage.py ingest_logs sample_logs/generated_auth.log")
    print("  python manage.py ingest_logs sample_logs/generated_firewall.log")
    print("  python manage.py ingest_logs sample_logs/generated_web.log")
