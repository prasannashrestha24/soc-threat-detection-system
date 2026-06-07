# 🛡 SOC Threat Detection System

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
- **CSV export** — download all alerts with auto-generated timestamp filename
- **Realistic log generator** — Python script simulating 4000+ log lines with real attack scenarios

## Tech Stack

- Python 3, Django, SQLite
- Custom log parsers (regex-based)
- Django management commands for log ingestion
- HTML/CSS dashboard (dark SOC theme)

## Quick Start

```bash
git clone https://github.com/prasannashrestha24/soc-threat-detection-system
cd soc-threat-detection-system
pip install django
python manage.py migrate
python generate_logs.py
python manage.py ingest_logs sample_logs/generated_auth.log
python manage.py ingest_logs sample_logs/generated_firewall.log
python manage.py ingest_logs sample_logs/generated_web.log
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
soc-threat-detection-system/
├── logs/
│   ├── models.py                      # LogEntry model
│   ├── parsers.py                     # Auth/firewall/web log parsers
│   └── management/commands/ingest_logs.py
├── alerts/
│   ├── models.py                      # Alert model
│   ├── rules.py                       # Detection rules engine
│   └── views.py                       # Dashboard + CSV export views
├── templates/dashboard/               # Dashboard UI
├── sample_logs/                       # Test log files
└── generate_logs.py                   # Realistic log generator script
```

## Development Log

### Week 1-2 — Project Setup & Initial Deployment

Built the core Django project structure with two apps — `logs` for ingesting and parsing security log files, and `alerts` for storing and displaying security alerts. Implemented custom log parsers using regex to handle three log formats: Linux auth logs, firewall logs, and Apache/Nginx web server logs. Created four automated detection rules covering brute force attacks, port scanning, credential stuffing, and after-hours logins. Built a dark-themed SOC dashboard displaying real-time alerts with severity classification. Pushed the full project to GitHub with clean commit history.

### Week 3-4 — Alert Management & Reporting

Added analyst workflow to the SOC dashboard. Security alerts can now be updated through four status stages — Open, Investigating, Resolved, and False Positive — mirroring real SOC triage processes. Added a one-click CSV export feature that downloads all current alerts with auto-generated timestamp filenames, enabling incident reporting and audit trail documentation.

### Week 5-6 — Realistic Dataset & Log Generator

Built a Python log generator script (`generate_logs.py`) that simulates realistic security attack scenarios instead of relying on a downloaded dataset. The script generates 4000+ log lines across three log types — auth, firewall, and web server logs. Five attack scenarios are simulated: SSH brute force attacks, credential stuffing from multiple IPs, after-hours logins, port scanning reconnaissance, and web application probing. Normal legitimate traffic is mixed in at 60-75% to make the dataset realistic. Running the generator and ingesting the logs produces a dashboard showing 4000+ real-looking security events with multiple alerts firing automatically.

---

## Author

Prasanna Shrestha — ICT Security Specialist Candidate | CIHE Canberra
GitHub: github.com/prasannashrestha24
