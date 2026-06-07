import csv
from django.shortcuts import render, get_object_or_404, redirect
from django.http import HttpResponse
from django.utils import timezone
from alerts.models import Alert
from logs.models import LogEntry

def dashboard(request):
    alerts = Alert.objects.all()
    context = {
        'alerts':        alerts,
        'recent_logs':   LogEntry.objects.all()[:20],
        'total_logs':    LogEntry.objects.count(),
        'total_alerts':  alerts.count(),
        'critical_count':alerts.filter(severity='critical').count(),
        'high_count':    alerts.filter(severity='high').count(),
        'medium_count':  alerts.filter(severity='medium').count(),
        'open_alerts':   alerts.filter(status='open').count(),
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


def export_alerts_csv(request):
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    filename = f"soc_alerts_{timestamp}.csv"

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Severity', 'Rule', 'Source IP', 'Username', 'Description', 'Status', 'Triggered At'])

    for alert in Alert.objects.all():
        writer.writerow([
            alert.id,
            alert.severity.upper(),
            alert.get_rule_name_display(),
            alert.source_ip or '—',
            alert.username or '—',
            alert.description,
            alert.get_status_display(),
            alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S'),
        ])

    return response
