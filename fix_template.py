content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SOC Threat Detection System</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
    header h1 { font-size: 1.3rem; color: #58a6ff; }
    header span { font-size: 0.8rem; color: #8b949e; }
    .btn-export { background: #1f6feb; color: #fff; border: none; border-radius: 6px; padding: 8px 18px; font-size: 0.85rem; cursor: pointer; text-decoration: none; }
    .btn-export:hover { background: #388bfd; }
    .stats { display: flex; gap: 16px; padding: 24px 32px; flex-wrap: wrap; }
    .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px 28px; min-width: 150px; }
    .stat-card .number { font-size: 2rem; font-weight: bold; }
    .stat-card .label { font-size: 0.8rem; color: #8b949e; margin-top: 4px; }
    .critical { color: #f85149; } .high { color: #e3b341; } .medium { color: #58a6ff; } .low { color: #3fb950; }
    .section { padding: 0 32px 32px; }
    .section h2 { font-size: 1rem; color: #8b949e; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { text-align: left; padding: 10px 12px; background: #161b22; color: #8b949e; border-bottom: 1px solid #30363d; }
    td { padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }
    tr:hover td { background: #161b22; }
    .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-critical { background: #3d1515; color: #f85149; } .badge-high { background: #2d2011; color: #e3b341; }
    .badge-medium { background: #112030; color: #58a6ff; } .badge-low { background: #0f2318; color: #3fb950; }
    .badge-open { background: #1c2128; color: #c9d1d9; } .badge-investigating { background: #2d2011; color: #e3b341; }
    .badge-resolved { background: #0f2318; color: #3fb950; } .badge-false_positive { background: #1c2128; color: #6e7681; }
    .empty { color: #8b949e; font-style: italic; padding: 24px; text-align: center; }
    .status-form { display: flex; gap: 6px; align-items: center; }
    .status-select { background: #1c2128; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 4px 8px; font-size: 0.78rem; cursor: pointer; }
    .btn-update { background: #238636; color: #fff; border: none; border-radius: 6px; padding: 4px 12px; font-size: 0.78rem; cursor: pointer; }
    .btn-update:hover { background: #2ea043; }
    .notes-form { display: flex; gap: 6px; align-items: center; margin-top: 6px; }
    .notes-input { background: #1c2128; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 4px 8px; font-size: 0.78rem; width: 260px; }
    .notes-input:focus { outline: none; border-color: #58a6ff; }
    .btn-note { background: #6e40c9; color: #fff; border: none; border-radius: 6px; padding: 4px 12px; font-size: 0.78rem; cursor: pointer; }
    .btn-note:hover { background: #8957e5; }
    .existing-note { font-size: 0.78rem; color: #8b949e; font-style: italic; margin-top: 4px; }
    .filter-bar { display: flex; gap: 12px; align-items: center; margin-bottom: 16px; flex-wrap: wrap; }
    .filter-select { background: #1c2128; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 6px 12px; font-size: 0.85rem; cursor: pointer; }
    .btn-filter { background: #1f6feb; color: #fff; border: none; border-radius: 6px; padding: 6px 16px; font-size: 0.85rem; cursor: pointer; }
    .btn-filter:hover { background: #388bfd; }
    .btn-clear { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; border-radius: 6px; padding: 6px 16px; font-size: 0.85rem; cursor: pointer; text-decoration: none; }
    .btn-clear:hover { background: #30363d; }
    .filter-label { font-size: 0.85rem; color: #8b949e; }
    .active-filter { font-size: 0.78rem; color: #58a6ff; margin-left: 4px; }
    .charts-row { display: flex; gap: 24px; padding: 0 32px 32px; flex-wrap: wrap; }
    .chart-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; flex: 1; min-width: 280px; max-width: 380px; }
    .chart-card h3 { font-size: 0.85rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 16px; }
  </style>
</head>
<body>
<header>
  <div>
    <h1>SOC Threat Detection System</h1>
    <span>Real-time threat detection &amp; alert monitoring | Canberra</span>
  </div>
  <a href="{% url 'export_alerts_csv' %}" class="btn-export">Export Alerts CSV</a>
</header>

<div class="stats">
  <div class="stat-card"><div class="number">{{ total_logs }}</div><div class="label">Total Log Entries</div></div>
  <div class="stat-card"><div class="number">{{ total_alerts }}</div><div class="label">Total Alerts</div></div>
  <div class="stat-card"><div class="number critical">{{ critical_count }}</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="number high">{{ high_count }}</div><div class="label">High</div></div>
  <div class="stat-card"><div class="number medium">{{ medium_count }}</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="number">{{ open_alerts }}</div><div class="label">Open Alerts</div></div>
</div>

<!-- Charts Row -->
<div class="charts-row">
  <div class="chart-card">
    <h3>Alerts by Severity</h3>
    <canvas id="severityChart" height="200"></canvas>
  </div>
  <div class="chart-card">
    <h3>Alerts by Rule</h3>
    <canvas id="ruleChart" height="200"></canvas>
  </div>
  <div class="chart-card">
    <h3>Alerts by Status</h3>
    <canvas id="statusChart" height="200"></canvas>
  </div>
</div>

<div class="section">
  <h2>Active Alerts
    {% if severity_filter or status_filter or rule_filter %}
    <span class="active-filter">— filtered</span>
    {% endif %}
  </h2>

  <form method="GET" action="/">
    <div class="filter-bar">
      <span class="filter-label">Filter by:</span>
      <select name="severity" class="filter-select">
        <option value="">All Severities</option>
        <option value="critical" {% if severity_filter == "critical" %}selected{% endif %}>Critical</option>
        <option value="high"     {% if severity_filter == "high" %}selected{% endif %}>High</option>
        <option value="medium"   {% if severity_filter == "medium" %}selected{% endif %}>Medium</option>
        <option value="low"      {% if severity_filter == "low" %}selected{% endif %}>Low</option>
      </select>
      <select name="status" class="filter-select">
        <option value="">All Statuses</option>
        <option value="open"           {% if status_filter == "open" %}selected{% endif %}>Open</option>
        <option value="investigating"  {% if status_filter == "investigating" %}selected{% endif %}>Investigating</option>
        <option value="resolved"       {% if status_filter == "resolved" %}selected{% endif %}>Resolved</option>
        <option value="false_positive" {% if status_filter == "false_positive" %}selected{% endif %}>False Positive</option>
      </select>
      <select name="rule" class="filter-select">
        <option value="">All Rules</option>
        <option value="brute_force"       {% if rule_filter == "brute_force" %}selected{% endif %}>Brute Force</option>
        <option value="after_hours_login" {% if rule_filter == "after_hours_login" %}selected{% endif %}>After Hours Login</option>
        <option value="port_scan"         {% if rule_filter == "port_scan" %}selected{% endif %}>Port Scan</option>
        <option value="multiple_failures" {% if rule_filter == "multiple_failures" %}selected{% endif %}>Credential Stuffing</option>
      </select>
      <button type="submit" class="btn-filter">Apply Filter</button>
      <a href="/" class="btn-clear">Clear</a>
    </div>
  </form>

  {% if alerts %}
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>Rule</th><th>Source IP</th><th>Username</th>
        <th>Description</th><th>Status</th><th>Time</th><th>Actions</th>
      </tr>
    </thead>
    <tbody>
      {% for alert in alerts %}
      <tr>
        <td><span class="badge badge-{{ alert.severity }}">{{ alert.severity }}</span></td>
        <td>{{ alert.get_rule_name_display }}</td>
        <td>{{ alert.source_ip|default:"&mdash;" }}</td>
        <td>{{ alert.username|default:"&mdash;" }}</td>
        <td>{{ alert.description }}</td>
        <td><span class="badge badge-{{ alert.status }}">{{ alert.get_status_display }}</span></td>
        <td>{{ alert.triggered_at|date:"d M H:i" }}</td>
        <td>
          <form method="POST" action="{% url 'update_alert_status' alert.id %}" class="status-form">
            {% csrf_token %}
            <select name="status" class="status-select">
              <option value="open"           {% if alert.status == "open" %}selected{% endif %}>Open</option>
              <option value="investigating"  {% if alert.status == "investigating" %}selected{% endif %}>Investigating</option>
              <option value="resolved"       {% if alert.status == "resolved" %}selected{% endif %}>Resolved</option>
              <option value="false_positive" {% if alert.status == "false_positive" %}selected{% endif %}>False Positive</option>
            </select>
            <button type="submit" class="btn-update">Update</button>
          </form>
          <form method="POST" action="{% url 'save_analyst_note' alert.id %}" class="notes-form">
            {% csrf_token %}
            <input type="text" name="analyst_notes" class="notes-input"
              placeholder="Add analyst note..."
              value="{{ alert.analyst_notes }}">
            <button type="submit" class="btn-note">Save Note</button>
          </form>
          {% if alert.analyst_notes %}
          <div class="existing-note">&#128203; {{ alert.analyst_notes }}</div>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No alerts match the current filter.</div>
  {% endif %}
</div>

<div class="section">
  <h2>Recent Log Entries (last 20)</h2>
  {% if recent_logs %}
  <table>
    <thead>
      <tr><th>Time</th><th>Source</th><th>IP</th><th>User</th><th>Action</th><th>Details</th></tr>
    </thead>
    <tbody>
      {% for log in recent_logs %}
      <tr>
        <td>{{ log.timestamp|date:"d M H:i:s" }}</td>
        <td>{{ log.get_source_display }}</td>
        <td>{{ log.source_ip|default:"&mdash;" }}</td>
        <td>{{ log.username|default:"&mdash;" }}</td>
        <td>{{ log.action }}</td>
        <td>{{ log.details|truncatechars:80 }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No log entries yet.</div>
  {% endif %}
</div>

<script>
const chartDefaults = {
  plugins: { legend: { display: false } },
  scales: {
    x: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } },
    y: { ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: '#21262d' }, beginAtZero: true }
  }
};

// Severity chart
const sevData = {{ severity_data|safe }};
new Chart(document.getElementById('severityChart'), {
  type: 'bar',
  data: {
    labels: Object.keys(sevData),
    datasets: [{
      data: Object.values(sevData),
      backgroundColor: ['#f85149', '#e3b341', '#58a6ff', '#3fb950'],
      borderRadius: 4,
    }]
  },
  options: chartDefaults
});

// Rule chart
const ruleData = {{ rule_data|safe }};
new Chart(document.getElementById('ruleChart'), {
  type: 'bar',
  data: {
    labels: Object.keys(ruleData),
    datasets: [{
      data: Object.values(ruleData),
      backgroundColor: '#58a6ff',
      borderRadius: 4,
    }]
  },
  options: chartDefaults
});

// Status chart
const statusData = {{ status_data|safe }};
new Chart(document.getElementById('statusChart'), {
  type: 'doughnut',
  data: {
    labels: Object.keys(statusData),
    datasets: [{
      data: Object.values(statusData),
      backgroundColor: ['#c9d1d9', '#e3b341', '#3fb950', '#6e7681'],
      borderColor: '#161b22',
      borderWidth: 2,
    }]
  },
  options: {
    plugins: {
      legend: {
        display: true,
        labels: { color: '#8b949e', font: { size: 11 } }
      }
    }
  }
});
</script>
</body>
</html>"""

with open('templates/dashboard/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done - file written successfully")
