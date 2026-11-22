from pathlib import Path
import time

from django.conf import settings
from django.core.cache import cache
from django.core.management.base import BaseCommand, CommandError

from audit_logs.services import record_system_event


class Command(BaseCommand):
    help = "Watch PROTECTED_DATA_ROOT and log external create/remove/move-out events."

    def add_arguments(self, parser):
        parser.add_argument("--duration", type=int, default=0, help="Stop after this many seconds; 0 runs until interrupted.")

    def handle(self, *args, **options):
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
        except ImportError as exc:
            raise CommandError("Install requirements.txt to use monitor_folders (watchdog is required).") from exc

        root = Path(settings.PROTECTED_DATA_ROOT).resolve()
        root.mkdir(parents=True, exist_ok=True)

        class Handler(FileSystemEventHandler):
            def inside(self, path):
                try:
                    return Path(path).resolve().is_relative_to(root)
                except (OSError, ValueError):
                    return False

            def relative(self, path):
                try:
                    return Path(path).resolve().relative_to(root).as_posix()
                except (OSError, ValueError):
                    return str(path)

            def suppressed(self):
                return bool(cache.get("sentrytrace_monitor_suppress"))

            def on_created(self, event):
                if not event.is_directory and self.inside(event.src_path) and not self.suppressed():
                    record_system_event("external_file_created", self.relative(event.src_path),
                                        "File appeared under the protected root outside an app write.")

            def on_deleted(self, event):
                if not event.is_directory and self.inside(event.src_path) and not self.suppressed():
                    record_system_event("external_file_removed", self.relative(event.src_path),
                                        "A protected file was removed outside an app write.", severity="high")

            def on_moved(self, event):
                if event.is_directory or self.suppressed():
                    return
                if self.inside(event.src_path) and not self.inside(event.dest_path):
                    record_system_event("external_file_moved_out", self.relative(event.src_path),
                                        f"File moved outside the watched root to {event.dest_path}.", severity="high")
                elif self.inside(event.dest_path):
                    record_system_event("external_file_created", self.relative(event.dest_path),
                                        "A file was moved into the protected root outside an app write.")

        observer = Observer()
        observer.schedule(Handler(), str(root), recursive=True)
        observer.start()
        self.stdout.write(self.style.SUCCESS(f"Watching {root}. Press Ctrl+C to stop."))
        started = time.monotonic()
        try:
            while observer.is_alive():
                if options["duration"] and time.monotonic() - started >= options["duration"]:
                    break
                time.sleep(0.5)
        except KeyboardInterrupt:
            self.stdout.write("Stopping folder monitor.")
        finally:
            observer.stop()
            observer.join(timeout=5)
