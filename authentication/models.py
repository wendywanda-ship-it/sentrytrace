from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models, transaction
from django.core.exceptions import ValidationError
from django.utils import timezone
import hashlib
import json
from datetime import timezone as datetime_timezone

class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.role_name

class UserManager(BaseUserManager):
    def create_user(self, username, email, full_name, staff_id, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, full_name=full_name, staff_id=staff_id, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, full_name, staff_id, password=None, **extra_fields):
        extra_fields.setdefault('status', 'active')
        admin_role, _ = Role.objects.get_or_create(role_name='Administrator', defaults={'description': 'System Administrator'})
        extra_fields['role'] = admin_role
        return self.create_user(username, email, full_name, staff_id, password, **extra_fields)


class User(AbstractBaseUser):
    MFA_METHOD_CHOICES = [
        ("authenticator", "Google Authenticator"),
        ("email", "Email verification code"),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('active', 'Active'),
        ('on_leave', 'On Leave'),
        ('suspended', 'Suspended'),
        ('rejected', 'Rejected'),
    ]

    user_id = models.AutoField(primary_key=True)
    full_name = models.CharField(max_length=100)
    staff_id = models.CharField(max_length=50, unique=True)
    email = models.EmailField(unique=True)
    department = models.CharField(max_length=100, blank=True, null=True)
    username = models.CharField(max_length=150, unique=True)
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    mfa_enabled = models.BooleanField(default=False)
    mfa_method = models.CharField(max_length=20, choices=MFA_METHOD_CHOICES, default="authenticator")
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(blank=True, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'full_name', 'staff_id']

    def __str__(self):
        return self.username

    @property
    def is_staff(self):
        return self.status == "active" and self.role is not None and self.role.role_name.lower() == "administrator"

    @property
    def is_superuser(self):
        return self.is_staff

    def has_perm(self, perm, obj=None):
        return self.is_staff

    def has_module_perms(self, app_label):
        return self.is_staff


class ProtectedFolder(models.Model):
    folder_id = models.AutoField(primary_key=True)
    folder_path = models.CharField(max_length=255, unique=True)
    project_name = models.CharField(max_length=100)
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def clean(self):
        from .filesystem import clean_relative_path, InvalidProtectedPath
        try:
            self.folder_path = clean_relative_path(self.folder_path)
        except InvalidProtectedPath as exc:
            raise ValidationError({"folder_path": str(exc)})

    def __str__(self):
        return f"{self.project_name} ({self.folder_path})"

class FolderPermission(models.Model):
    permission_id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    folder = models.ForeignKey(ProtectedFolder, on_delete=models.CASCADE)
    can_view = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_copy = models.BooleanField(default=False)

    class Meta:
        unique_together = ('role', 'folder')

    def __str__(self):
        return f"{self.role.role_name} -> {self.folder.project_name} [V:{self.can_view} E:{self.can_edit} C:{self.can_copy}]"


class FilePermission(models.Model):
    """Role ACL for a file path relative to one protected folder."""
    permission_id = models.AutoField(primary_key=True)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    folder = models.ForeignKey(ProtectedFolder, on_delete=models.CASCADE, related_name="file_permissions")
    file_path = models.CharField(max_length=512)
    can_view = models.BooleanField(default=False)
    can_edit = models.BooleanField(default=False)
    can_copy = models.BooleanField(default=False)

    class Meta:
        unique_together = ("role", "folder", "file_path")
        ordering = ("folder__project_name", "file_path")

    def clean(self):
        from .filesystem import clean_relative_path, InvalidProtectedPath
        try:
            self.file_path = clean_relative_path(self.file_path)
        except InvalidProtectedPath as exc:
            raise ValidationError({"file_path": str(exc)})

    def __str__(self):
        return f"{self.role.role_name} -> {self.folder.project_name}/{self.file_path}"

class AccessLog(models.Model):
    log_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT, null=True, blank=True)
    folder = models.ForeignKey(ProtectedFolder, on_delete=models.PROTECT, null=True, blank=True)
    event_type = models.CharField(max_length=255)
    file_path = models.CharField(max_length=512, blank=True, null=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    event_time = models.DateTimeField(default=timezone.now, db_index=True)
    details = models.TextField(blank=True, default="")
    outcome = models.CharField(max_length=20, default="OK")
    prev_hash = models.CharField(max_length=64, default="0" * 64)
    entry_hash = models.CharField(max_length=64, blank=True, null=True)

    class QuerySet(models.QuerySet):
        def update(self, **kwargs):
            raise TypeError("AccessLog entries are append-only")

        def delete(self):
            raise TypeError("AccessLog entries are append-only")

        def bulk_create(self, *args, **kwargs):
            raise TypeError("AccessLog entries must be appended through create()")

        def bulk_update(self, *args, **kwargs):
            raise TypeError("AccessLog entries are append-only")

    objects = models.Manager.from_queryset(QuerySet)()

    def hash_payload(self):
        timestamp = self.event_time
        if timezone.is_naive(timestamp):
            timestamp = timezone.make_aware(timestamp, datetime_timezone.utc)
        timestamp = timestamp.astimezone(datetime_timezone.utc).isoformat(timespec="microseconds")
        return json.dumps({
            "prev_hash": self.prev_hash,
            "user_id": self.user_id,
            "folder_id": self.folder_id,
            "event_type": self.event_type,
            "file_path": self.file_path or "",
            "ip_address": self.ip_address or "",
            "event_time": timestamp,
            "details": self.details or "",
            "outcome": self.outcome,
        }, sort_keys=True, separators=(",", ":"))

    def save(self, *args, **kwargs):
        if self.pk and AccessLog.objects.filter(pk=self.pk).exists():
            raise TypeError("AccessLog entries are append-only")
        if not self.event_time:
            self.event_time = timezone.now()
        last_log = AccessLog.objects.order_by('-log_id').first()
        self.prev_hash = last_log.entry_hash if last_log and last_log.entry_hash else "0" * 64
        self.entry_hash = hashlib.sha256(self.hash_payload().encode('utf-8')).hexdigest()
        super().save(*args, **kwargs)
        transaction.on_commit(_advance_forensic_head)

    def delete(self, *args, **kwargs):
        raise TypeError("AccessLog entries are append-only")


def _advance_forensic_head():
    from audit_logs.integrity import write_current_head
    write_current_head()

class Alert(models.Model):
    ALERT_TYPES = [
        ('unauthorized_copy', 'Unauthorized Copy'),
        ('on_leave_login', 'On-Leave Login'),
        ('suspended_login', 'Suspended Account Login'),
        ('off_hours_login', 'Off-Hours Login'),
        ('unauthorized_access', 'Unauthorized Access Attempt'),
        ('admin_access_denied', 'Unauthorized Administrator Page Access'),
        ('rapid_copying', 'Rapid Copying'),
        ('folder_or', 'Protected Folder or Event'),
    ]
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('resolved', 'Resolved'),
    ]

    alert_id = models.AutoField(primary_key=True)
    log = models.OneToOneField(AccessLog, on_delete=models.CASCADE)
    alert_type = models.CharField(max_length=50, choices=ALERT_TYPES)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    created_at = models.DateTimeField(auto_now_add=True)
    resolved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='resolved_alerts')

    def __str__(self):
        return f"[{self.severity.upper()}] {self.alert_type} - {self.status}"

class Report(models.Model):
    report_id = models.AutoField(primary_key=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    date_from = models.DateField()
    date_to = models.DateField()
    department = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report {self.report_id} by {self.generated_by}"
