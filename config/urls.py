from django.contrib import admin
from django.urls import path
from alerts.views import dashboard, update_alert_status, save_analyst_note, export_alerts_csv

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', dashboard, name='dashboard'),
    path('alerts/<int:alert_id>/update-status/', update_alert_status, name='update_alert_status'),
    path('alerts/<int:alert_id>/save-note/', save_analyst_note, name='save_analyst_note'),
    path('alerts/export/csv/', export_alerts_csv, name='export_alerts_csv'),
]
