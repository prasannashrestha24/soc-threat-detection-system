from django.core.management.base import BaseCommand
from logs.models import LogEntry
from logs.parsers import parse_line
from alerts.rules import run_all_rules

class Command(BaseCommand):
    help = "Ingest a log file and run detection rules"

    def add_arguments(self, parser):
        parser.add_argument('log_file', type=str, help="Path to log file")

    def handle(self, *args, **options):
        path = options['log_file']
        parsed = 0
        skipped = 0
        self.stdout.write(f"Ingesting: {path}")
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                result = parse_line(line)
                if result:
                    LogEntry.objects.create(**result)
                    parsed += 1
                else:
                    skipped += 1
        self.stdout.write(self.style.SUCCESS(f"Done - {parsed} lines ingested, {skipped} skipped"))
        self.stdout.write("Running detection rules...")
        run_all_rules()
        self.stdout.write(self.style.SUCCESS("Rules complete. Check dashboard for alerts."))
