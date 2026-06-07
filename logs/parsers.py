"""
Log parsers — one function per log type.
Each parser reads a raw log line and returns a dict
that can be used to create a LogEntry object.

Phase 1 covers: auth logs, firewall logs, web server logs.
"""

import re
from datetime import datetime
from zoneinfo import ZoneInfo

TIMEZONE = ZoneInfo("Australia/Sydney")


def parse_auth_log(line: str) -> dict | None:
    """
    Parses Linux-style auth log lines.
    Example:
      Jun  3 02:15:44 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2
    """
    pattern = re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+\S+:\s+(.*)'
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    time_str, message = match.groups()

    # Add current year (auth logs don't include year)
    year = datetime.now().year
    try:
        timestamp = datetime.strptime(f"{year} {time_str.strip()}", "%Y %b %d %H:%M:%S")
        timestamp = timestamp.replace(tzinfo=TIMEZONE)
    except ValueError:
        return None

    action = "UNKNOWN"
    username = None
    source_ip = None

    if "Failed password" in message:
        action = "FAILED_LOGIN"
        user_match = re.search(r'for (\S+) from ([\d.]+)', message)
        if user_match:
            username, source_ip = user_match.groups()

    elif "Accepted password" in message or "Accepted publickey" in message:
        action = "SUCCESSFUL_LOGIN"
        user_match = re.search(r'for (\S+) from ([\d.]+)', message)
        if user_match:
            username, source_ip = user_match.groups()

    elif "Invalid user" in message:
        action = "INVALID_USER"
        user_match = re.search(r'Invalid user (\S+) from ([\d.]+)', message)
        if user_match:
            username, source_ip = user_match.groups()

    return {
        'timestamp': timestamp,
        'source': 'auth',
        'source_ip': source_ip,
        'username': username,
        'action': action,
        'details': message,
        'raw_line': line,
    }


def parse_firewall_log(line: str) -> dict | None:
    """
    Parses simple firewall log lines.
    Example:
      2026-06-03 03:22:11 BLOCK TCP 203.0.113.5 -> 10.0.0.1 port=22
    """
    pattern = re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(BLOCK|ALLOW)\s+(\S+)\s+([\d.]+)\s+->\s+([\d.]+)\s+port=(\d+)'
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    time_str, verdict, protocol, src_ip, dst_ip, port = match.groups()

    try:
        timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        timestamp = timestamp.replace(tzinfo=TIMEZONE)
    except ValueError:
        return None

    action = "BLOCKED" if verdict == "BLOCK" else "ALLOWED"

    return {
        'timestamp': timestamp,
        'source': 'firewall',
        'source_ip': src_ip,
        'username': None,
        'action': action,
        'details': f"{protocol} {src_ip} -> {dst_ip}:{port}",
        'raw_line': line,
    }


def parse_web_log(line: str) -> dict | None:
    """
    Parses Apache/Nginx combined log format.
    Example:
      203.0.113.5 - - [03/Jun/2026:02:15:44 +1000] "GET /admin HTTP/1.1" 401 512
    """
    pattern = re.compile(
        r'([\d.]+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+\d+'
    )
    match = pattern.match(line.strip())
    if not match:
        return None

    src_ip, time_str, method, path, status_code = match.groups()

    try:
        timestamp = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None

    action = f"{method}_{status_code}"

    return {
        'timestamp': timestamp,
        'source': 'web',
        'source_ip': src_ip,
        'username': None,
        'action': action,
        'details': f"{method} {path} -> HTTP {status_code}",
        'raw_line': line,
    }


def parse_line(line: str) -> dict | None:
    """
    Auto-detect log type and parse.
    Try each parser in order — return first match.
    """
    for parser in [parse_auth_log, parse_firewall_log, parse_web_log]:
        result = parser(line)
        if result:
            return result
    return None
