from django.db import models
from logs.models import LogEntry

class Alert(models.Model):
    """
    Generated when a detection rule is triggered.
    Severity mirrors real SOC classifications.
    """
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high',     'High'),
        ('medium',   'Medium'),
        ('low',      'Low'),
    ]

    STATUS_CHOICES = [
        ('open',        'Open'),
        ('investigating','Investigating'),
        ('resolved',    'Resolved'),
        ('false_positive', 'False Positive'),
    ]

    RULE_CHOICES = [
        ('brute_force',       'Brute Force Attack'),
        ('after_hours_login', 'After Hours Login'),
        ('port_scan',         'Port Scan Detected'),
        ('multiple_failures', 'Multiple Auth Failures'),
    ]

    rule_name       = models.CharField(max_length=50, choices=RULE_CHOICES)
    severity        = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    source_ip       = models.GenericIPAddressField(null=True, blank=True)
    username        = models.CharField(max_length=100, null=True, blank=True)
    description     = models.TextField()
    triggered_at    = models.DateTimeField(auto_now_add=True)
    related_logs    = models.ManyToManyField(LogEntry, blank=True)
    analyst_notes   = models.TextField(blank=True)

    class Meta:
        ordering = ['-triggered_at']

    def __str__(self):
        return f"[{self.severity.upper()}] {self.rule_name} | {self.source_ip} | {self.triggered_at}"
