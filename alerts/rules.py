"""
Detection rules engine.
Each rule function analyses recent LogEntry records
and creates Alert objects when thresholds are exceeded.

To add a new rule:
  1. Write a function following the pattern below
  2. Register it in RULES list at the bottom
"""

from datetime import timedelta
from django.utils import timezone
from django.db.models import Count
from logs.models import LogEntry
from alerts.models import Alert


def rule_brute_force(window_minutes=5, threshold=5):
    """
    Trigger: Same IP has 5+ failed logins within 5 minutes.
    Severity: Critical
    Real-world: SSH brute force, password spraying
    """
    since = timezone.now() - timedelta(minutes=window_minutes)

    offenders = (
        LogEntry.objects
        .filter(source='auth', action='FAILED_LOGIN', timestamp__gte=since)
        .values('source_ip')
        .annotate(count=Count('id'))
        .filter(count__gte=threshold)
    )

    for offender in offenders:
        ip = offender['source_ip']

        # Don't duplicate — skip if open alert already exists for this IP
        if Alert.objects.filter(rule_name='brute_force', source_ip=ip, status='open').exists():
            continue

        related = LogEntry.objects.filter(
            source='auth', action='FAILED_LOGIN',
            source_ip=ip, timestamp__gte=since
        )

        alert = Alert.objects.create(
            rule_name='brute_force',
            severity='critical',
            source_ip=ip,
            description=(
                f"Brute force attack detected: {offender['count']} failed login attempts "
                f"from {ip} in the last {window_minutes} minutes."
            ),
        )
        alert.related_logs.set(related)


def rule_after_hours_login(start_hour=8, end_hour=18):
    """
    Trigger: Successful login outside business hours (before 8am or after 6pm).
    Severity: Medium
    Real-world: Compromised account used outside normal working hours
    """
    since = timezone.now() - timedelta(hours=1)

    recent_logins = LogEntry.objects.filter(
        source='auth',
        action='SUCCESSFUL_LOGIN',
        timestamp__gte=since
    )

    for log in recent_logins:
        hour = log.timestamp.hour
        if hour < start_hour or hour >= end_hour:

            if Alert.objects.filter(
                rule_name='after_hours_login',
                source_ip=log.source_ip,
                username=log.username,
                status='open'
            ).exists():
                continue

            alert = Alert.objects.create(
                rule_name='after_hours_login',
                severity='medium',
                source_ip=log.source_ip,
                username=log.username,
                description=(
                    f"After-hours login detected: user '{log.username}' logged in "
                    f"from {log.source_ip} at {log.timestamp.strftime('%H:%M')} "
                    f"(outside business hours {start_hour}:00–{end_hour}:00)."
                ),
            )
            alert.related_logs.set([log])


def rule_port_scan(window_minutes=2, unique_port_threshold=10):
    """
    Trigger: Same IP blocked on 10+ different connection attempts in 2 minutes.
    Severity: High
    Real-world: Network reconnaissance / port scanning
    """
    since = timezone.now() - timedelta(minutes=window_minutes)

    offenders = (
        LogEntry.objects
        .filter(source='firewall', action='BLOCKED', timestamp__gte=since)
        .values('source_ip')
        .annotate(count=Count('id'))
        .filter(count__gte=unique_port_threshold)
    )

    for offender in offenders:
        ip = offender['source_ip']

        if Alert.objects.filter(rule_name='port_scan', source_ip=ip, status='open').exists():
            continue

        related = LogEntry.objects.filter(
            source='firewall', action='BLOCKED',
            source_ip=ip, timestamp__gte=since
        )

        alert = Alert.objects.create(
            rule_name='port_scan',
            severity='high',
            source_ip=ip,
            description=(
                f"Port scan detected: {offender['count']} blocked connection attempts "
                f"from {ip} in the last {window_minutes} minutes."
            ),
        )
        alert.related_logs.set(related)


def rule_multiple_auth_failures(window_hours=1, threshold=3):
    """
    Trigger: Same username fails login from 3+ different IPs within 1 hour.
    Severity: High
    Real-world: Credential stuffing or distributed brute force
    """
    since = timezone.now() - timedelta(hours=window_hours)

    offenders = (
        LogEntry.objects
        .filter(source='auth', action='FAILED_LOGIN', timestamp__gte=since)
        .exclude(username=None)
        .values('username')
        .annotate(unique_ips=Count('source_ip', distinct=True))
        .filter(unique_ips__gte=threshold)
    )

    for offender in offenders:
        username = offender['username']

        if Alert.objects.filter(
            rule_name='multiple_failures', username=username, status='open'
        ).exists():
            continue

        related = LogEntry.objects.filter(
            source='auth', action='FAILED_LOGIN',
            username=username, timestamp__gte=since
        )

        alert = Alert.objects.create(
            rule_name='multiple_failures',
            severity='high',
            username=username,
            description=(
                f"Credential stuffing suspected: user '{username}' failed login "
                f"from {offender['unique_ips']} different IPs in the last {window_hours} hour(s)."
            ),
        )
        alert.related_logs.set(related)


# ── Register all rules here ──────────────────────────────────────────────────
# To disable a rule, just comment it out.
RULES = [
    rule_brute_force,
    rule_after_hours_login,
    rule_port_scan,
    rule_multiple_auth_failures,
]


def run_all_rules():
    """Run every registered detection rule."""
    for rule in RULES:
        try:
            rule()
        except Exception as e:
            print(f"[RULE ERROR] {rule.__name__}: {e}")
