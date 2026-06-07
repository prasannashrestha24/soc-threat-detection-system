# 🛡 SIEM Lite — Security Monitoring Dashboard

A Python/Django-based security log monitoring system that ingests, parses, and analyses auth, firewall, and web server logs to detect suspicious activity and generate security alerts.

Built as a portfolio project demonstrating core SOC/SIEM concepts.

---

## Features

- **Log ingestion** — parses Linux auth logs, firewall logs, and Apache/Nginx web logs
- **Detection rules engine** — 4 rules covering real-world attack patterns:
  - Brute force attack detection (SSH failed logins)
  - After-hours login detection
  - Port scan detection
  - Credential stuffing detection
- **Security dashboard** — real-time alert display with severity classification
- **Alert management** — open/investigating/resolved/false positive status tracking

## Tech Stack

- Python 3, Django, SQLite
- Custom log parsers (regex-based)
- Django management commands for log ingestion
- HTML/CSS dashboard (dark SOC theme)

## Quick Start

```bash
git clone https://github.com/yourusername/siem-lite-dashboard
cd siem-lite-dashboard
pip install django
python manage.py migrate
python manage.py ingest_logs sample_logs/auth.log
python manage.py ingest_logs sample_logs/firewall.log
python manage.py ingest_logs sample_logs/web.log
python manage.py runserver
```
Visit http://127.0.0.1:8000 to see the dashboard.

## Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Brute Force | 5+ failed logins from same IP in 5 min | Critical |
| After Hours Login | Successful login outside 08:00–18:00 | Medium |
| Port Scan | 10+ blocked connections from same IP in 2 min | High |
| Credential Stuffing | Same username failed from 3+ IPs in 1 hour | High |

## Project Structure

```
siem-lite/
├── logs/
│   ├── models.py          # LogEntry model
│   ├── parsers.py         # Auth/firewall/web log parsers
│   └── management/commands/ingest_logs.py
├── alerts/
│   ├── models.py          # Alert model
│   ├── rules.py           # Detection rules engine
│   └── views.py           # Dashboard view
├── templates/dashboard/   # Dashboard UI
└── sample_logs/           # Test log files
```

## Author

Prasanna Shrestha — ICT Security Specialist candidate, Canberra ACT
