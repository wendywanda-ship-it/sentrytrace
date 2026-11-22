import hashlib
from functools import wraps

from django.core.cache import cache
from django.contrib.auth.views import redirect_to_login

MAX_FAILED_ATTEMPTS = 5
WINDOW_SECONDS = 5 * 60


def _key(request, username, stage):
    address = request.META.get("REMOTE_ADDR", "unknown")
    raw = f"{stage}|{address}|{username.strip().casefold()}"
    return "sentrytrace:auth:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_rate_limited(request, username, stage="login"):
    return (cache.get(_key(request, username, stage), 0) or 0) >= MAX_FAILED_ATTEMPTS


def record_failed_attempt(request, username, stage="login"):
    key = _key(request, username, stage)
    if not cache.add(key, 1, timeout=WINDOW_SECONDS):
        try:
            cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=WINDOW_SECONDS)


def clear_failed_attempts(request, username, stage="login"):
    cache.delete(_key(request, username, stage))


def secure_login_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            from audit_logs.services import record_alert_event
            record_alert_event("anonymous_access_denied", request,
                               details=f"Anonymous request to {request.path}",
                               alert_type="unauthorized_access", severity="high", outcome="BLOCKED")
            return redirect_to_login(request.get_full_path())
        return view_func(request, *args, **kwargs)
    return wrapped
