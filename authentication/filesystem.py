from pathlib import Path, PurePosixPath
import shutil

from django.conf import settings
from django.core.cache import cache


class InvalidProtectedPath(ValueError):
    pass


def clean_relative_path(value):
    if not value or "\\" in value or "\x00" in value:
        raise InvalidProtectedPath("Use a non-empty POSIX path relative to the protected root.")
    raw = PurePosixPath(value)
    if raw.is_absolute() or any(part in {"..", "."} for part in raw.parts):
        raise InvalidProtectedPath("Path traversal is not allowed.")
    if any(part.endswith((".", " ")) or any(char in part for char in '<>:"|?*') for part in raw.parts):
        raise InvalidProtectedPath("Path contains a character that is unsafe on the supported platforms.")
    normalized = str(raw)
    if normalized in {"", "."}:
        raise InvalidProtectedPath("A relative path is required.")
    return normalized


def protected_path(*parts, must_exist=False):
    root = Path(settings.PROTECTED_DATA_ROOT).resolve()
    clean_parts = [clean_relative_path(str(part)) for part in parts if str(part)]
    target = root.joinpath(*clean_parts).resolve(strict=must_exist)
    if target != root and root not in target.parents:
        raise InvalidProtectedPath("Resolved path escapes the protected data root.")
    return target


def folder_disk_path(folder, *, must_exist=False):
    return protected_path(folder.folder_path, must_exist=must_exist)


def file_disk_path(folder, relative_path, *, must_exist=False):
    return protected_path(folder.folder_path, relative_path, must_exist=must_exist)


def app_write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    cache.set("sentrytrace_monitor_suppress", True, timeout=5)
    path.write_bytes(data)


def app_copy_file(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    cache.set("sentrytrace_monitor_suppress", True, timeout=5)
    shutil.copy2(source, destination)
