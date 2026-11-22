"""Shared helpers for SentryTrace's protected folders and files."""

from pathlib import Path
from types import SimpleNamespace
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from audit_logs.services import record_alert_event, record_auth_event
from .filesystem import InvalidProtectedPath, app_copy_file, app_write_bytes, file_disk_path, folder_disk_path
from .models import AccessLog, Alert, FilePermission, FolderPermission, ProtectedFolder


def _is_administrator(user):
    try:
        return bool(user.is_authenticated and user.role and user.role.role_name.casefold() == "administrator")
    except (AttributeError, ObjectDoesNotExist):
        return False


def accessible_folders(user):
    """Return folders visible through the user's role ACLs."""
    if _is_administrator(user):
        return ProtectedFolder.objects.all().order_by("project_name")
    if not getattr(user, "role_id", None):
        return ProtectedFolder.objects.none()
    folder_acl = FolderPermission.objects.filter(role=user.role)
    folder_ids = set(folder_acl.filter(can_view=True).values_list("folder_id", flat=True))
    configured_ids = folder_acl.values_list("folder_id", flat=True)
    folder_ids.update(
        FilePermission.objects.filter(role=user.role, can_view=True)
        .exclude(folder_id__in=configured_ids)
        .values_list("folder_id", flat=True)
    )
    return ProtectedFolder.objects.filter(folder_id__in=folder_ids).order_by("project_name")


def permission_for(user, folder):
    """Return the folder ACL, effective file-ACL summary, or admin full-access flags."""
    if _is_administrator(user):
        return SimpleNamespace(can_view=True, can_edit=True, can_copy=True)
    if not getattr(user, "role_id", None):
        return None
    permission = FolderPermission.objects.filter(role=user.role, folder=folder).first()
    if permission:
        return permission
    file_acls = FilePermission.objects.filter(role=user.role, folder=folder)
    if not file_acls.exists():
        return None
    return SimpleNamespace(
        can_view=file_acls.filter(can_view=True).exists(),
        can_edit=file_acls.filter(can_edit=True).exists(),
        can_copy=file_acls.filter(can_copy=True).exists(),
    )


def list_files(folder):
    """List sorted relative file paths, returning an empty list for unavailable folders."""
    try:
        disk_folder = folder_disk_path(folder, must_exist=True)
        return sorted(
            path.relative_to(disk_folder).as_posix()
            for path in disk_folder.rglob("*")
            if path.is_file() and safe_file_path(folder, path.relative_to(disk_folder).as_posix()) is not None
        )
    except (OSError, InvalidProtectedPath, ValueError):
        return []


def safe_file_path(folder, filename):
    """Resolve a filename only when its real path stays inside the selected folder."""
    try:
        folder_root = folder_disk_path(folder, must_exist=True).resolve(strict=True)
        target = file_disk_path(folder, str(filename)).resolve(strict=False)
        if target != folder_root and folder_root in target.parents:
            return target
    except (OSError, InvalidProtectedPath, ValueError, TypeError):
        pass
    return None


def read_file(path):
    """Read up to 20,000 characters from a regular text file under the protected root."""
    try:
        root = Path(settings.PROTECTED_DATA_ROOT).resolve(strict=True)
        target = Path(path).resolve(strict=True)
        if not target.is_file() or root not in target.parents:
            return ""
        with target.open("r", encoding="utf-8") as stream:
            return stream.read(20_000)
    except (OSError, UnicodeError, ValueError, TypeError):
        return ""


def write_file(path, content):
    """Write at most 200,000 characters to a file under the protected root."""
    root = Path(settings.PROTECTED_DATA_ROOT).resolve(strict=True)
    target = Path(path).resolve(strict=False)
    if target == root or root not in target.parents:
        raise InvalidProtectedPath("Resolved file path escapes the protected data root.")
    truncated = str(content)[:200_000]
    app_write_bytes(target, truncated.encode("utf-8"))
    return len(truncated)


def _destination_file_allowed(user, folder, filename):
    if _is_administrator(user):
        return True
    if not getattr(user, "role_id", None):
        return False
    folder_acl = FolderPermission.objects.filter(role=user.role, folder=folder).first()
    file_acl = FilePermission.objects.filter(role=user.role, folder=folder, file_path=filename).first()
    if folder_acl and not folder_acl.can_edit:
        return False
    if file_acl:
        return bool(file_acl.can_edit)
    return bool(folder_acl and folder_acl.can_edit)


def attempt_copy(user, src_folder, src_perm, src_path, destination, ip, destination_name=None):
    """Authorize and copy one protected file, logging every outcome and rapid-copy alert."""
    request = SimpleNamespace(user=user, META={"REMOTE_ADDR": ip or ""})
    try:
        source_root = folder_disk_path(src_folder, must_exist=True).resolve(strict=True)
        source_candidate = Path(src_path)
        if not source_candidate.is_absolute():
            source_candidate = source_root / source_candidate
        source = source_candidate.resolve(strict=True)
        if not source.is_file() or source_root not in source.parents:
            raise InvalidProtectedPath("Invalid protected source file.")
        destination_root = folder_disk_path(destination, must_exist=True).resolve(strict=True)
        if not destination_root.is_dir():
            raise InvalidProtectedPath("Protected destination folder is unavailable.")
    except (OSError, InvalidProtectedPath, ValueError, TypeError):
        message = "Copy denied: invalid or unavailable protected source or destination."
        record_alert_event("copy_denied", request, user=user, details=message,
                           alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                           folder=src_folder, path=str(src_path)[:512])
        return False, message

    relative_source = source.relative_to(source_root).as_posix()
    source_allowed = _is_administrator(user) or bool(src_perm and getattr(src_perm, "can_copy", False))
    if not source_allowed:
        message = "Copy denied: source copy permission is not granted."
        record_alert_event("copy_denied", request, user=user, details=message,
                           alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                           folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
        return False, message

    if not _is_administrator(user):
        destination_acl = permission_for(user, destination)
        if not destination_acl or not destination_acl.can_edit:
            message = "Copy denied: destination write permission is not granted."
            record_alert_event("copy_denied", request, user=user, details=message,
                               alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                               folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
            return False, message

    requested_name = destination_name or source.name
    try:
        candidate_path = file_disk_path(destination, requested_name)
        requested_name = candidate_path.relative_to(destination_root).as_posix()
    except (OSError, InvalidProtectedPath, ValueError):
        message = "Copy denied: invalid protected destination path."
        record_alert_event("copy_denied", request, user=user, details=message,
                           alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                           folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
        return False, message
    candidate = candidate_path
    suffix = 1
    while candidate.exists():
        requested = Path(requested_name)
        unique_name = requested.with_name(f"{requested.stem} ({suffix}){requested.suffix}").as_posix()
        try:
            candidate = file_disk_path(destination, unique_name)
        except (OSError, InvalidProtectedPath, ValueError):
            message = "Copy denied: invalid protected destination path."
            record_alert_event("copy_denied", request, user=user, details=message,
                               alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                               folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
            return False, message
        suffix += 1
    destination_name = candidate.relative_to(destination_root).as_posix()
    if not _destination_file_allowed(user, destination, destination_name):
        message = "Copy denied: destination file write permission is not granted."
        record_alert_event("copy_denied", request, user=user, details=message,
                           alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                           folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
        return False, message

    try:
        safe_destination = file_disk_path(destination, destination_name)
        app_copy_file(source, safe_destination)
    except (OSError, InvalidProtectedPath, ValueError):
        message = "Copy denied: protected destination could not be written."
        record_alert_event("copy_denied", request, user=user, details=message,
                           alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                           folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}")
        return False, message

    copy_log = record_auth_event(
        "copy_ok", request, user,
        f"Destination: {destination.folder_path}/{destination_name}",
        folder=src_folder, path=f"{src_folder.folder_path}/{relative_source}", outcome="OK",
    )
    recent_copies = AccessLog.objects.filter(
        user=user, event_type="copy_ok", event_time__gte=copy_log.event_time - timedelta(seconds=60)
    ).count()
    if recent_copies == 3:
        Alert.objects.create(log=copy_log, alert_type="rapid_copying", severity="high")
    return True, f"Copied to {destination.project_name}/{destination_name}."
