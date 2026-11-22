import secrets
from pathlib import Path

import pyotp
from django.conf import settings
from django.core.management.base import BaseCommand

from authentication.filesystem import app_write_bytes, folder_disk_path
from authentication.models import FilePermission, FolderPermission, ProtectedFolder, Role, User


class Command(BaseCommand):
    help = "Create idempotent DEMO ONLY users, protected folders, files, and permissions."

    def _create_account(self, username, role, status, *, department="Demo Research"):
        existing = User.objects.filter(username=username).first()
        if existing:
            return existing, None, None, False

        password = secrets.token_urlsafe(18)
        secret = pyotp.random_base32() if status == "active" else None
        email_base = f"{username}@example.test"
        email = email_base
        suffix = 1
        while User.objects.filter(email__iexact=email).exists():
            email = f"{username}-{suffix}@example.test"
            suffix += 1
        staff_base = f"DEMO-{username.upper()}"
        staff_id = staff_base[:50]
        suffix = 1
        while User.objects.filter(staff_id=staff_id).exists():
            staff_id = f"{staff_base[:40]}-{suffix}"
            suffix += 1
        user = User.objects.create_user(
            username=username,
            email=email,
            full_name=username.replace("-", " ").title(),
            staff_id=staff_id,
            password=password,
            department=department,
            role=role,
            status=status,
            totp_secret=secret,
            mfa_enabled=secret is not None,
        )
        return user, password, secret, True

    def _folder(self, path, name, owner):
        folder, _ = ProtectedFolder.objects.get_or_create(
            folder_path=path,
            defaults={"project_name": name, "owner": owner},
        )
        folder_disk_path(folder).mkdir(parents=True, exist_ok=True)
        return folder

    def _sample_file(self, folder, filename, content):
        path = folder_disk_path(folder) / filename
        if not path.exists():
            app_write_bytes(path, content.encode("utf-8"))

    def _ensure_folder_permission(self, role, folder, **permissions):
        FolderPermission.objects.update_or_create(role=role, folder=folder, defaults=permissions)

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING(
            "DEMO ONLY - change these passwords before any real use."
        ))
        roles = {}
        for name, description in (
            ("Administrator", "Full SentryTrace administration"),
            ("Researcher", "Research data access subject to ACLs"),
            ("Auditor", "Read-only security event review"),
        ):
            roles[name], _ = Role.objects.get_or_create(role_name=name, defaults={"description": description})

        # Preserve the existing demo fixtures as well as the diploma-demo account names below.
        for username, role_name, status in (
            ("demo-admin", "Administrator", "active"),
            ("demo-researcher", "Researcher", "active"),
            ("demo-onleave", "Researcher", "on_leave"),
            ("demo-pending", "Researcher", "pending"),
        ):
            user, password, secret, created = self._create_account(username, roles[role_name], status)
            if created:
                self.stdout.write(f"{username} / {password} ({status}; {role_name})")
                if secret:
                    self.stdout.write(f"  DEMO ONLY authenticator key: {secret}")
            else:
                self.stdout.write(f"Existing demo account retained: {username}; credentials unchanged.")

        demo_owner = User.objects.filter(username="demo-admin").first()
        source = self._folder("demo/research", "Demo Research", demo_owner)
        destination = self._folder("demo/output", "Demo Output", demo_owner)
        self._sample_file(source, "readme.txt", "Sample research notes.\n")
        self._sample_file(source, "restricted.txt", "Copying this file is denied for Researchers.\n")
        researcher = roles["Researcher"]
        self._ensure_folder_permission(researcher, source, can_view=True, can_edit=True, can_copy=True)
        self._ensure_folder_permission(researcher, destination, can_view=True, can_edit=True, can_copy=False)
        FilePermission.objects.get_or_create(
            role=researcher, folder=source, file_path="readme.txt",
            defaults={"can_view": True, "can_edit": True, "can_copy": True},
        )
        FilePermission.objects.get_or_create(
            role=researcher, folder=source, file_path="restricted.txt",
            defaults={"can_view": True, "can_edit": False, "can_copy": False},
        )

        diploma_accounts = []
        for username, role_name, status in (
            ("admin", "Administrator", "active"),
            ("jmwangi", "Researcher", "active"),
            ("kndiritu", "Researcher", "on_leave"),
            ("newstaff", None, "pending"),
        ):
            role = roles.get(role_name) if role_name else None
            user, password, secret, created = self._create_account(username, role, status)
            diploma_accounts.append({
                "username": username,
                "role": role_name or "None",
                "status": user.status,
                "password": password if created else "existing; unchanged",
                "key": secret if created and secret else ("—" if created else "existing; not displayed"),
            })

        genomics = self._folder("genomics", "Genomics Project", User.objects.filter(username="admin").first())
        outputs = self._folder("outputs", "Public Outputs", User.objects.filter(username="admin").first())
        self._sample_file(genomics, "genomics_v3.csv", "sample_id,reading\nG-001,0.82\nG-002,0.91")
        self._sample_file(genomics, "notes.txt", "Confidential genomics project notes.")
        self._sample_file(outputs, "summary.txt", "Public summary of results.")
        self._sample_file(outputs, "survey.csv", "id,score\n1,4\n2,5")
        self._ensure_folder_permission(
            researcher, genomics, can_view=True, can_edit=True, can_copy=False,
        )
        self._ensure_folder_permission(
            researcher, outputs, can_view=True, can_edit=True, can_copy=True,
        )

        self.stdout.write("\nDiploma demo account credentials (new passwords and keys are printed only on creation):")
        headers = ("Username", "Role", "Status", "Password", "Authenticator key")
        widths = (12, 18, 12, 30, 28)
        self.stdout.write(" | ".join(value.ljust(width) for value, width in zip(headers, widths)))
        self.stdout.write("-+-".join("-" * width for width in widths))
        for account in diploma_accounts:
            self.stdout.write(" | ".join(account[key][:width].ljust(width) for key, width in zip(
                ("username", "role", "status", "password", "key"), widths,
            )))
        self.stdout.write(self.style.SUCCESS(
            f"Protected demo folders and files are ready under {Path(settings.PROTECTED_DATA_ROOT)}."
        ))
