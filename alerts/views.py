import csv
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from django.utils import timezone
from alerts.models import Alert
from logs.models import LogEntry

def dashboard(request):
    alerts = Alert.objects.all()

    # Filtering
    severity_filter = request.GET.get('severity', '')
    status_filter   = request.GET.get('status', '')
    rule_filter     = request.GET.get('rule', '')

    if severity_filter:
        alerts = alerts.filter(severity=severity_filter)
    if status_filter:
        alerts = alerts.filter(status=status_filter)
    if rule_filter:
        alerts = alerts.filter(rule_name=rule_filter)

    all_alerts = Alert.objects.all()
    context = {
        'alerts':          alerts,
        'recent_logs':     LogEntry.objects.all()[:20],
        'total_logs':      LogEntry.objects.count(),
        'total_alerts':    all_alerts.count(),
        'critical_count':  all_alerts.filter(severity='critical').count(),
        'high_count':      all_alerts.filter(severity='high').count(),
        'medium_count':    all_alerts.filter(severity='medium').count(),
        'open_alerts':     all_alerts.filter(status='open').count(),
        'severity_filter': severity_filter,
        'status_filter':   status_filter,
        'rule_filter':     rule_filter,
    }
    return render(request, 'dashboard/index.html', context)


def update_alert_status(request, alert_id):
    if request.method == 'POST':
        alert = get_object_or_404(Alert, id=alert_id)
        new_status = request.POST.get('status')
        valid_statuses = ['open', 'investigating', 'resolved', 'false_positive']
        if new_status in valid_statuses:
            alert.status = new_status
            alert.save()
    return redirect('dashboard')


def save_analyst_note(request, alert_id):
    if request.method == 'POST':
        alert = get_object_or_404(Alert, id=alert_id)
        note = request.POST.get('analyst_notes', '').strip()
        alert.analyst_notes = note
        alert.save()
    return redirect('dashboard')


def export_alerts_csv(request):
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    filename = f"soc_alerts_{timestamp}.csv"

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Severity', 'Rule', 'Source IP', 'Username', 'Description', 'Status', 'Analyst Notes', 'Triggered At'])

    for alert in Alert.objects.all():
        writer.writerow([
            alert.id,
            alert.severity.upper(),
            alert.get_rule_name_display(),
            alert.source_ip or '—',
            alert.username or '—',
            alert.description,
            alert.get_status_display(),
            alert.analyst_notes or '',
            alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S'),
        ])

    return response
