from django.db import models

class LogEntry(models.Model):
    """
    Represents a single parsed log line from any source.
    Supports: auth logs, firewall logs, web server logs
    """
    LOG_SOURCES = [
        ('auth', 'Auth Log'),
        ('firewall', 'Firewall Log'),
        ('web', 'Web Server Log'),
    ]

    timestamp       = models.DateTimeField()
    source          = models.CharField(max_length=20, choices=LOG_SOURCES)
    source_ip       = models.GenericIPAddressField(null=True, blank=True)
    username        = models.CharField(max_length=100, null=True, blank=True)
    action          = models.CharField(max_length=100)   # e.g. "FAILED_LOGIN", "BLOCKED", "GET"
    details         = models.TextField(blank=True)
    raw_line        = models.TextField()
    ingested_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.source.upper()}] {self.timestamp} | {self.source_ip} | {self.action}"
