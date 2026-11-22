import hashlib
import base64
import re
import tempfile
from pathlib import Path
from datetime import datetime, timezone as dt_timezone
from io import StringIO
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.management import call_command
from django.core import mail

from audit_logs.integrity import verify_integrity
from audit_logs.reports import safe_csv_cell
from .filesystem import InvalidProtectedPath, file_disk_path
from .core_files import accessible_folders, list_files, permission_for, read_file, safe_file_path, write_file
from .models import AccessLog, Alert, FilePermission, FolderPermission, ProtectedFolder, Report, Role, User


class SentryTraceFlowTests(TestCase):
    def setUp(self):
        cache.clear()
        self.temp_root = tempfile.TemporaryDirectory()
        self.settings_override = override_settings(PROTECTED_DATA_ROOT=Path(self.temp_root.name),
                                                   AUDIT_HEAD_FILE=Path(self.temp_root.name) / "audit-head")
        self.settings_override.enable()
        self.staff_role, _ = Role.objects.get_or_create(role_name="Researcher")
        self.admin_role, _ = Role.objects.get_or_create(role_name="Administrator")
        self.staff = User.objects.create_user(
            username="analyst", email="analyst@example.test", full_name="Test Analyst",
            staff_id="ST-001", password="Safe-Test-Password-81!", status="active",
            role=self.staff_role, totp_secret=pyotp.random_base32(), mfa_enabled=True,
        )
        self.folder = ProtectedFolder.objects.create(folder_path="classified/project", project_name="Classified")
        self.destination = ProtectedFolder.objects.create(folder_path="classified/output", project_name="Output")
        Path(self.temp_root.name, "classified", "project").mkdir(parents=True)
        Path(self.temp_root.name, "classified", "output").mkdir(parents=True)
        Path(self.temp_root.name, "classified", "project", "summary.txt").write_text("protected research\n", encoding="utf-8")
        self.file_acl = FilePermission.objects.create(
            role=self.staff_role, folder=self.folder, file_path="summary.txt",
            can_view=True, can_edit=True, can_copy=True,
        )
        FolderPermission.objects.create(role=self.staff_role, folder=self.folder, can_view=True, can_copy=True)
        FolderPermission.objects.create(role=self.staff_role, folder=self.destination, can_view=True, can_edit=True)

    def tearDown(self):
        self.settings_override.disable()
        self.temp_root.cleanup()

    def login_mfa(self):
        self.client.force_login(self.staff)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()

    def test_registration_requires_password_confirmation_and_creates_pending_user(self):
        data = {"username": "newuser", "email": "new@example.test", "full_name": "New User",
                "staff_id": "ST-002", "department": "Operations", "password": "Strong-Unique-Password-982!",
                "password_confirm": "different"}
        response = self.client.post(reverse("register"), data)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="newuser").exists())
        data["password_confirm"] = data["password"]
        response = self.client.post(reverse("register"), data)
        self.assertRedirects(response, reverse("login"))
        user = User.objects.get(username="newuser")
        self.assertEqual(user.status, "pending")
        self.assertTrue(user.check_password(data["password"]))

    def test_pending_account_cannot_log_in(self):
        self.staff.status = "pending"
        self.staff.save(update_fields=["status"])
        response = self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertTrue(AccessLog.objects.filter(event_type="login_denied", outcome="BLOCKED").exists())

    def test_password_alone_never_grants_dashboard_access_and_totp_does(self):
        old_session_key = self.client.session.session_key
        self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        self.assertNotEqual(self.client.session.session_key, old_session_key)
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, reverse("mfa_verify"))
        self.assertFalse(self.client.session.get("mfa_verified"))
        response = self.client.post(reverse("mfa_verify"), {"verification_code": pyotp.TOTP(self.staff.totp_secret).now()})
        self.assertRedirects(response, reverse("dashboard"))
        self.assertTrue(self.client.session.get("mfa_verified"))

    def _start_email_mfa_enrollment(self):
        self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        response = self.client.get(reverse("mfa_verify"))
        self.assertContains(response, "Set up multi-factor security")
        with patch("authentication.views.secrets.randbelow", return_value=123456):
            response = self.client.post(reverse("mfa_verify"), {"mfa_method": "email"})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Verify your email")
        self.assertEqual(len(mail.outbox), 1)
        return re.search(r"\b\d{6}\b", mail.outbox[-1].body).group(0)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_email_mfa_enrollment_sends_code_and_requires_verification_before_dashboard(self):
        self.staff.mfa_enabled = False
        self.staff.save(update_fields=["mfa_enabled"])
        code = self._start_email_mfa_enrollment()
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, reverse("mfa_verify"))
        self.assertFalse(self.client.session.get("mfa_verified"))

        response = self.client.post(reverse("mfa_verify"), {"verification_code": code})
        self.assertRedirects(response, reverse("dashboard"))
        self.staff.refresh_from_db()
        self.assertTrue(self.staff.mfa_enabled)
        self.assertEqual(self.staff.mfa_method, "email")
        self.assertTrue(self.client.session.get("mfa_verified"))
        self.assertFalse(AccessLog.objects.filter(details__contains=code).exists())

    @override_settings(
        EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
        EMAIL_HOST="",
    )
    def test_email_mfa_explains_when_smtp_is_not_configured(self):
        self.staff.mfa_enabled = False
        self.staff.save(update_fields=["mfa_enabled"])
        self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        response = self.client.post(reverse("mfa_verify"), {"mfa_method": "email"})
        self.assertContains(response, "Email OTP is not configured")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_email_mfa_rejects_incorrect_expired_and_reused_codes(self):
        self.staff.mfa_enabled = False
        self.staff.save(update_fields=["mfa_enabled"])
        code = self._start_email_mfa_enrollment()
        response = self.client.post(reverse("mfa_verify"), {"verification_code": "999999"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.session.get("mfa_verified"))

        session = self.client.session
        session["mfa_email_otp_expires_at"] = 1
        session.save()
        self.assertEqual(self.client.session.get("mfa_email_otp_expires_at"), 1)
        response = self.client.post(reverse("mfa_verify"), {"verification_code": code})
        self.assertEqual(response.status_code, 200, response.get("Location"))
        self.assertFalse(self.client.session.get("mfa_verified"))

        new_code = self.client.post(reverse("mfa_verify"), {"resend_email_otp": "1"})
        self.assertEqual(new_code.status_code, 200)
        current_code = re.search(r"\b\d{6}\b", mail.outbox[-1].body).group(0)
        self.client.post(reverse("mfa_verify"), {"verification_code": current_code})
        self.client.post(reverse("logout"))
        with patch("authentication.views.secrets.randbelow", return_value=777777):
            self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        response = self.client.post(reverse("mfa_verify"), {"verification_code": current_code})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.session.get("mfa_verified"))

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_email_mfa_resend_cooldown_invalidates_previous_code(self):
        self.staff.mfa_enabled = False
        self.staff.save(update_fields=["mfa_enabled"])
        old_code = self._start_email_mfa_enrollment()
        sent_at = self.client.session["mfa_email_otp_sent_at"]
        with patch("authentication.views.time.time", return_value=sent_at + 61), \
             patch("authentication.views.secrets.randbelow", return_value=654321):
            response = self.client.post(reverse("mfa_verify"), {"resend_email_otp": "1"})
        self.assertContains(response, "A new verification code was sent")
        new_code = re.search(r"\b\d{6}\b", mail.outbox[-1].body).group(0)
        self.assertNotEqual(old_code, new_code)
        response = self.client.post(reverse("mfa_verify"), {"verification_code": old_code})
        self.assertFalse(self.client.session.get("mfa_verified"))
        response = self.client.post(reverse("mfa_verify"), {"verification_code": new_code})
        self.assertRedirects(response, reverse("dashboard"))

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_email_mfa_verification_is_rate_limited(self):
        self.staff.mfa_enabled = False
        self.staff.save(update_fields=["mfa_enabled"])
        self._start_email_mfa_enrollment()
        for _ in range(5):
            self.client.post(reverse("mfa_verify"), {"verification_code": "000000"})
        response = self.client.post(reverse("mfa_verify"), {"verification_code": "000000"})
        self.assertEqual(response.status_code, 429)

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_existing_authenticator_user_can_switch_to_email_from_mfa_settings(self):
        self.login_mfa()
        response = self.client.post(reverse("mfa_verify"), {
            "change_mfa_method": "1", "mfa_method": "email",
        })
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.session.get("mfa_verified"))
        self.assertEqual(len(mail.outbox), 1)
        code = re.search(r"\b\d{6}\b", mail.outbox[-1].body).group(0)
        response = self.client.post(reverse("mfa_verify"), {"verification_code": code})
        self.assertRedirects(response, reverse("dashboard"))
        self.staff.refresh_from_db()
        self.assertEqual(self.staff.mfa_method, "email")
        self.assertTrue(self.staff.mfa_enabled)
        self.assertEqual(self.client.session.get_expiry_age(), 900)

    def test_wrong_totp_is_rejected_and_logged(self):
        self.client.force_login(self.staff)
        response = self.client.post(reverse("mfa_verify"), {"verification_code": "000000"})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.client.session.get("mfa_verified"))
        self.assertTrue(AccessLog.objects.filter(event_type="mfa_denied", outcome="BLOCKED").exists())

    def test_totp_attempts_are_rate_limited_after_five_failures(self):
        self.client.force_login(self.staff)
        for _ in range(5):
            response = self.client.post(reverse("mfa_verify"), {"verification_code": "000000"})
            self.assertEqual(response.status_code, 200)
        response = self.client.post(reverse("mfa_verify"), {"verification_code": "000000"})
        self.assertEqual(response.status_code, 429)

    def test_off_hours_login_is_flagged(self):
        self.client.force_login(self.staff)
        code = pyotp.TOTP(self.staff.totp_secret).now()
        with patch("authentication.views.timezone.localtime", return_value=datetime(2026, 11, 16, 21, 0, tzinfo=dt_timezone.utc)):
            response = self.client.post(reverse("mfa_verify"), {"verification_code": code})
        self.assertRedirects(response, reverse("dashboard"))
        self.assertTrue(Alert.objects.filter(alert_type="off_hours_login", severity="medium").exists())

    def test_new_enrollment_secret_is_not_saved_before_confirmation(self):
        self.staff.mfa_enabled = False
        self.staff.totp_secret = None
        self.staff.save(update_fields=["mfa_enabled", "totp_secret"])
        self.client.force_login(self.staff)
        response = self.client.get(reverse("mfa_verify"))
        self.assertEqual(response.status_code, 200)
        self.staff.refresh_from_db()
        self.assertIsNone(self.staff.totp_secret)
        session_secret = self.client.session["mfa_enrollment_secret"]
        response = self.client.post(reverse("mfa_verify"), {"verification_code": pyotp.TOTP(session_secret).now()})
        self.assertRedirects(response, reverse("dashboard"))
        self.staff.refresh_from_db()
        self.assertEqual(self.staff.totp_secret, session_secret)

    def test_on_leave_login_is_blocked_and_alerted(self):
        self.staff.status = "on_leave"
        self.staff.save(update_fields=["status"])
        self.client.post(reverse("login"), {"username": "analyst", "password": "Safe-Test-Password-81!"})
        self.assertTrue(Alert.objects.filter(alert_type="on_leave_login", severity="high").exists())

    def test_login_attempts_are_rate_limited_per_ip_and_username(self):
        for _ in range(5):
            self.client.post(reverse("login"), {"username": "analyst", "password": "wrong"})
        response = self.client.post(reverse("login"), {"username": "analyst", "password": "wrong"})
        self.assertEqual(response.status_code, 429)

    def test_account_status_change_ends_existing_session(self):
        self.login_mfa()
        self.staff.status = "suspended"
        self.staff.save(update_fields=["status"])
        response = self.client.get(reverse("dashboard"))
        self.assertRedirects(response, reverse("login"))
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertTrue(Alert.objects.filter(alert_type="suspended_login").exists())

    def test_file_rbac_allow_and_deny_is_audited_and_alerted(self):
        FilePermission.objects.create(role=self.staff_role, folder=self.folder, file_path="secret.txt", can_view=False)
        self.login_mfa()
        allowed = self.client.get(reverse("protected_file", args=[self.folder.pk, "summary.txt"]))
        self.assertEqual(allowed.status_code, 200)
        self.assertContains(allowed, "protected research")
        denied = self.client.get(reverse("protected_file", args=[self.folder.pk, "secret.txt"]))
        self.assertEqual(denied.status_code, 403)
        self.assertTrue(AccessLog.objects.filter(outcome="BLOCKED").exists())
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_access").exists())

    def test_researcher_can_open_authorized_folder_detail(self):
        self.login_mfa()
        self.assertIn(self.folder, accessible_folders(self.staff))
        self.assertTrue(permission_for(self.staff, self.folder).can_view)
        response = self.client.get(reverse("folder_detail", args=[self.folder.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "summary.txt")
        self.assertEqual(list_files(self.folder), ["summary.txt"])

    def test_core_file_helpers_enforce_paths_and_size_limits(self):
        safe = safe_file_path(self.folder, "summary.txt")
        self.assertIsNotNone(safe)
        self.assertIsNone(safe_file_path(self.folder, "../outside.txt"))
        self.assertEqual(read_file(safe), "protected research\n")
        written = write_file(safe, "x" * 200_005)
        self.assertEqual(written, 200_000)
        self.assertEqual(len(safe.read_text(encoding="utf-8")), 200_000)
        self.assertEqual(len(read_file(safe)), 20_000)

    def test_researcher_without_folder_access_is_blocked_logged_and_alerted(self):
        denied_folder = ProtectedFolder.objects.create(folder_path="classified/denied", project_name="Denied")
        Path(self.temp_root.name, "classified", "denied").mkdir(parents=True)
        self.login_mfa()
        response = self.client.get(reverse("folder_detail", args=[denied_folder.pk]))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(AccessLog.objects.filter(folder=denied_folder, outcome="BLOCKED").exists())
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_access", log__folder=denied_folder).exists())

    def test_edit_without_permission_is_blocked_logged_and_alerted(self):
        self.login_mfa()
        response = self.client.get(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {"action": "edit"})
        self.assertEqual(response.status_code, 403)
        self.assertTrue(AccessLog.objects.filter(event_type="edit_denied", outcome="BLOCKED").exists())
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_access").exists())

    def test_copy_to_unprotected_destination_is_blocked_and_alerted(self):
        unprotected = ProtectedFolder.objects.create(folder_path="classified/unprotected", project_name="Unprotected")
        Path(self.temp_root.name, "classified", "unprotected").mkdir(parents=True)
        self.login_mfa()
        response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
            "action": "copy", "destination_folder_id": unprotected.pk,
        })
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_copy", severity="high").exists())

    def test_folder_detail_traversal_returns_page_with_no_selected_file(self):
        self.login_mfa()
        response = self.client.get(reverse("folder_detail", args=[self.folder.pk]), {"filename": "../outside.txt"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["selected"])
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_access", severity="high").exists())

    def test_explicit_file_deny_beats_folder_allow(self):
        self.file_acl.can_view = False
        self.file_acl.save()
        self.login_mfa()
        response = self.client.get(reverse("protected_file", args=[self.folder.pk, "summary.txt"]))
        self.assertEqual(response.status_code, 403)

    def test_blocked_copy_raises_high_alert(self):
        self.file_acl.can_copy = False
        self.file_acl.save()
        self.login_mfa()
        response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
            "action": "copy", "destination_folder_id": self.destination.pk,
        })
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_copy", severity="high").exists())

    def test_permitted_copy_requires_destination_write_permission(self):
        self.login_mfa()
        response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
            "action": "copy", "destination_folder_id": self.destination.pk, "destination_file_path": "copy.txt",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Path(self.temp_root.name, "classified", "output", "copy.txt").read_text(encoding="utf-8"), "protected research\n")
        self.assertTrue(AccessLog.objects.filter(event_type="copy_ok").exists())

    def test_copy_uses_unique_name_when_destination_file_already_exists(self):
        Path(self.temp_root.name, "classified", "output", "copy.txt").write_text("existing", encoding="utf-8")
        self.login_mfa()
        response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
            "action": "copy", "destination_folder_id": self.destination.pk, "destination_file_path": "copy.txt",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Path(self.temp_root.name, "classified", "output", "copy (1).txt").read_text(encoding="utf-8"), "protected research\n")

    def test_copy_without_destination_write_is_blocked_and_alerted(self):
        FolderPermission.objects.filter(folder=self.destination, role=self.staff_role).update(can_edit=False)
        self.login_mfa()
        response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
            "action": "copy", "destination_folder_id": self.destination.pk,
        })
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Alert.objects.filter(alert_type="unauthorized_copy", severity="high").exists())

    def test_path_traversal_is_rejected_for_acl_and_storage_paths(self):
        bad = FilePermission.objects.create(role=self.staff_role, folder=self.folder, file_path="../secret.txt", can_view=True)
        self.login_mfa()
        response = self.client.get(reverse("file_action", args=[self.folder.pk, bad.pk, "view"]))
        self.assertEqual(response.status_code, 403)
        with self.assertRaises(InvalidProtectedPath):
            file_disk_path(self.folder, "../outside.txt")

    def test_three_copies_in_one_minute_raise_rapid_copying_alert(self):
        self.login_mfa()
        for name in ("one.txt", "two.txt", "three.txt"):
            response = self.client.post(reverse("protected_file", args=[self.folder.pk, "summary.txt"]), {
                "action": "copy", "destination_folder_id": self.destination.pk, "destination_file_path": name,
            })
            self.assertEqual(response.status_code, 302)
        self.assertTrue(Alert.objects.filter(alert_type="rapid_copying", severity="high").exists())

    def test_hash_chain_valid_and_append_only_guards_reject_mutations(self):
        first = AccessLog.objects.create(user=self.staff, event_type="test_first")
        second = AccessLog.objects.create(user=self.staff, event_type="test_second")
        self.assertEqual(second.prev_hash, first.entry_hash)
        self.assertTrue(verify_integrity(check_anchor=False)["valid"])
        with self.assertRaises(TypeError):
            first.save()
        with self.assertRaises(TypeError):
            AccessLog.objects.filter(pk=first.pk).update(details="tampered")
        with self.assertRaises(TypeError):
            AccessLog.objects.filter(pk=first.pk).delete()

    def test_hash_chain_detects_content_tampering_and_middle_deletion(self):
        first = AccessLog.objects.create(user=self.staff, event_type="first")
        second = AccessLog.objects.create(user=self.staff, event_type="second")
        third = AccessLog.objects.create(user=self.staff, event_type="third")
        with self.assertRaises(TypeError):
            first.details = "tampered"
            first.save()
        self.assertTrue(verify_integrity(check_anchor=False)["valid"])
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("UPDATE authentication_accesslog SET details = %s WHERE log_id = %s", ["tampered", second.pk])
        self.assertFalse(verify_integrity(check_anchor=False)["valid"])
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM authentication_accesslog WHERE log_id = %s", [second.pk])
        result = verify_integrity(check_anchor=False)
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_bad_id"], third.pk)

    def test_external_checkpoint_detects_tail_deletion(self):
        from audit_logs.integrity import write_current_head
        first = AccessLog.objects.create(user=self.staff, event_type="anchored_first")
        last = AccessLog.objects.create(user=self.staff, event_type="anchored_last")
        write_current_head(force=True)
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM authentication_accesslog WHERE log_id = %s", [last.pk])
        result = verify_integrity()
        self.assertFalse(result["valid"])

    def test_rfc_6238_six_digit_vector(self):
        encoded_secret = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")
        self.assertEqual(pyotp.TOTP(encoded_secret, digits=6, interval=30).at(59), "287082")

    def test_csv_formula_injection_is_neutralized(self):
        for value in ("=1+1", "+cmd", "-2", "@SUM(A1)", "  =HYPERLINK('x')"):
            self.assertTrue(safe_csv_cell(value).lstrip().startswith("'"))
        self.assertEqual(safe_csv_cell("ordinary text"), "ordinary text")

    def test_non_admin_admin_access_is_blocked_logged_and_alerted(self):
        self.login_mfa()
        response = self.client.get(reverse("admin_dashboard"))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Alert.objects.filter(alert_type="admin_access_denied").exists())

    def test_registration_approval_assigns_selected_role(self):
        admin = User.objects.create_user(username="admin", email="admin@example.test", full_name="Admin",
                                         staff_id="ST-ADMIN", password="Safe-Admin-Password-92!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        pending = User.objects.create_user(username="pending", email="pending@example.test", full_name="Pending",
                                           staff_id="ST-PENDING", password="Safe-Pending-Password-82!")
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("approve_user", args=[pending.pk]), {"role_id": self.staff_role.pk})
        self.assertRedirects(response, reverse("pending_users"))
        pending.refresh_from_db()
        self.assertEqual(pending.status, "active")
        self.assertEqual(pending.role, self.staff_role)

    def test_management_pages_render_for_admin(self):
        admin = User.objects.create_user(username="page-admin", email="page-admin@example.test", full_name="Page Admin",
                                         staff_id="PAGE-ADMIN", password="Page-Admin-Password-14!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        self.assertEqual(self.client.get(reverse("admin_dashboard")).status_code, 200)
        self.assertEqual(self.client.get(reverse("pending_users")).status_code, 200)
        self.assertEqual(self.client.get(reverse("admin_access_management")).status_code, 200)
        self.assertEqual(self.client.get(reverse("manage_folders")).status_code, 200)
        self.assertEqual(self.client.get(reverse("alert_list")).status_code, 200)
        self.assertEqual(self.client.get(reverse("report_view")).status_code, 200)

    def test_admin_folder_permission_grid_saves_role_permissions(self):
        admin = User.objects.create_user(username="grid-admin", email="grid@example.test", full_name="Grid Admin",
                                         staff_id="GRID-ADMIN", password="Grid-Admin-Password-14!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("manage_folders"), {
            "action": "folder_acl_grid", "folder_id": self.folder.pk,
            f"role_{self.staff_role.pk}_can_view": "on",
            f"role_{self.staff_role.pk}_can_edit": "on",
        })
        self.assertRedirects(response, reverse("manage_folders"))
        permission = FolderPermission.objects.get(role=self.staff_role, folder=self.folder)
        self.assertTrue(permission.can_view)
        self.assertTrue(permission.can_edit)
        self.assertFalse(permission.can_copy)

    def test_admin_creating_folder_creates_real_directory_and_rejects_traversal(self):
        admin = User.objects.create_user(username="folder-admin", email="folder@example.test", full_name="Folder Admin",
                                         staff_id="FOLDER-ADMIN", password="Folder-Admin-Password-14!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("manage_folders"), {
            "action": "create_folder", "project_name": "New Project", "folder_path": "created/project",
        })
        self.assertRedirects(response, reverse("manage_folders"))
        self.assertTrue(Path(self.temp_root.name, "created", "project").is_dir())
        self.assertIsNotNone(ProtectedFolder.objects.get(folder_path="created/project").created_at)
        self.client.post(reverse("manage_folders"), {
            "action": "create_folder", "project_name": "Outside", "folder_path": "../outside",
        })
        self.assertFalse(ProtectedFolder.objects.filter(project_name="Outside").exists())

    def test_role_catalog_and_custom_roles_are_available_in_admin_forms(self):
        admin = User.objects.create_user(username="roles-admin", email="roles@example.test", full_name="Roles Admin",
                                         staff_id="ROLES-ADMIN", password="Roles-Admin-Password-14!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()

        catalog = {"Other", "Staff", "Department Manager", "Human Resources", "IT Administrator",
                   "Security Analyst", "Security Officer", "Compliance Officer", "Legal Officer",
                   "Finance Officer", "Project Manager", "Operations"}
        self.assertTrue(catalog.issubset(set(Role.objects.values_list("role_name", flat=True))))

        response = self.client.post(reverse("pending_users"), {
            "role_name": "Clinical Data Steward", "description": "Controls clinical research data access.",
        })
        self.assertRedirects(response, reverse("pending_users"))
        custom_role = Role.objects.get(role_name="Clinical Data Steward")
        self.assertEqual(custom_role.description, "Controls clinical research data access.")

        users_page = self.client.get(reverse("pending_users"))
        access_page = self.client.get(reverse("admin_access_management"))
        self.assertContains(users_page, "Other")
        self.assertContains(users_page, "Clinical Data Steward")
        self.assertContains(access_page, "Other")
        self.assertContains(access_page, "Clinical Data Steward")

    def test_duplicate_role_creation_is_rejected_without_creating_duplicate(self):
        admin = User.objects.create_user(username="duplicate-admin", email="duplicate@example.test", full_name="Duplicate Admin",
                                         staff_id="DUPLICATE-ADMIN", password="Duplicate-Admin-Password-14!",
                                         role=self.admin_role, status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("pending_users"), {"role_name": "  researcher  "})
        self.assertRedirects(response, reverse("pending_users"))
        self.assertEqual(Role.objects.filter(role_name__iexact="Researcher").count(), 1)

    def test_seed_demo_is_idempotent_and_prints_demo_credentials(self):
        first, second = StringIO(), StringIO()
        call_command("seed_demo", stdout=first)
        demo_users = User.objects.filter(username__startswith="demo-").count()
        call_command("seed_demo", stdout=second)
        self.assertEqual(demo_users, 4)
        self.assertEqual(User.objects.filter(username__startswith="demo-").count(), 4)
        self.assertIn("DEMO ONLY", first.getvalue())
        self.assertIn("demo-admin", first.getvalue())


class ReportExportTests(TestCase):
    def test_csv_injection_prefixes_formula_leading_values(self):
        self.assertEqual(safe_csv_cell("=1+1"), "'=1+1")

    def test_admin_can_download_pdf_and_report_is_saved(self):
        admin_role, _ = Role.objects.get_or_create(role_name="Administrator")
        admin = User.objects.create_user(username="report-admin", email="report@example.test", full_name="Report Admin",
                                         staff_id="REPORT-ADMIN", password="Report-Password-123!", role=admin_role,
                                         status="active", totp_secret=pyotp.random_base32(), mfa_enabled=True)
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        response = self.client.post(reverse("report_view"), {
            "date_from": "2026-11-01", "date_to": "2026-11-16", "department": "", "format": "pdf",
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(Report.objects.count(), 1)

    def test_csv_export_neutralizes_formula_cells(self):
        from audit_logs.reports import export_csv
        row = AccessLog.objects.create(event_type="test", details="=HYPERLINK('bad')")
        response = export_csv([row])
        self.assertIn(b"'=HYPERLINK", response.content)


class DeleteUserTests(TestCase):
    def setUp(self):
        self.temp_root = tempfile.TemporaryDirectory()
        self.settings_override = override_settings(
            AUDIT_HEAD_FILE=Path(self.temp_root.name) / "audit-head"
        )
        self.settings_override.enable()
        self.admin_role, _ = Role.objects.get_or_create(role_name="Administrator")
        self.staff_role, _ = Role.objects.get_or_create(role_name="Researcher")

    def tearDown(self):
        self.settings_override.disable()
        self.temp_root.cleanup()

    def _make_admin_and_login(self, username="delete-admin"):
        admin = User.objects.create_user(
            username=username,
            email=f"{username}@example.test",
            full_name="Delete Test Admin",
            staff_id=f"DELETE-{username.upper()}",
            password="Delete-Admin-Password-82!",
            status="active",
            role=self.admin_role,
            totp_secret=pyotp.random_base32(),
            mfa_enabled=True,
        )
        self.client.force_login(admin)
        session = self.client.session
        session["mfa_verified"] = True
        session.save()
        return admin

    def _make_target_user(self, username):
        return User.objects.create_user(
            username=username,
            email=f"{username}@example.test",
            full_name=username.title(),
            staff_id=f"TARGET-{username.upper()}",
            password="Target-User-Password-82!",
            status="active",
            role=self.staff_role,
        )

    def test_admin_can_delete_another_user_account_successfully(self):
        self._make_admin_and_login()
        target = self._make_target_user("target-a")

        response = self.client.post(reverse("delete_user", args=[target.pk]), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "was deleted.")

    def test_admin_cannot_delete_their_own_account(self):
        admin = self._make_admin_and_login()

        response = self.client.post(reverse("delete_user", args=[admin.pk]), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You cannot delete your own administrator account.")
        self.assertTrue(User.objects.filter(pk=admin.pk).exists())

    def test_admin_cannot_delete_the_system_account(self):
        self._make_admin_and_login()
        system_user = self._make_target_user("system")

        response = self.client.post(reverse("delete_user", args=[system_user.pk]), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The system account cannot be deleted.")
        self.assertTrue(User.objects.filter(pk=system_user.pk).exists())

    def test_non_admin_cannot_access_delete_url(self):
        target = self._make_target_user("target-non-admin")
        self.client.force_login(target)

        response = self.client.post(reverse("delete_user", args=[target.pk]))

        self.assertIn(response.status_code, (302, 403))
        self.assertTrue(User.objects.filter(pk=target.pk).exists())

    def test_deleted_user_no_longer_exists_in_database(self):
        self._make_admin_and_login()
        target = self._make_target_user("target-gone")
        target_pk = target.pk

        self.client.post(reverse("delete_user", args=[target_pk]))

        self.assertFalse(User.objects.filter(pk=target_pk).exists())

    def test_users_page_shows_delete_button_only_for_eligible_users(self):
        admin = self._make_admin_and_login()
        target = self._make_target_user("target-visible")
        system_user = self._make_target_user("system")

        response = self.client.get(reverse("pending_users"))

        self.assertContains(response, f'action="{reverse("delete_user", args=[target.pk])}"')
        self.assertNotContains(response, f'action="{reverse("delete_user", args=[admin.pk])}"')
        self.assertNotContains(response, f'action="{reverse("delete_user", args=[system_user.pk])}"')
