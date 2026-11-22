
import base64
import hashlib
import hmac
import io
import logging
import secrets
import time

import pyotp
import qrcode

from django.contrib import messages
from django.contrib.auth import (
    authenticate,
    login,
    logout,
    get_user_model,
)
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render, get_object_or_404
from django.http import HttpResponseForbidden
from django.http import FileResponse, HttpResponse, HttpResponseNotAllowed
from django.contrib.auth.password_validation import validate_password
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db.models import Count
from django.views.decorators.http import require_POST
from functools import wraps
from django.utils import timezone
from audit_logs.services import record_alert_event, record_auth_event, record_file_event
from audit_logs.integrity import verify_integrity
from .models import AccessLog, Alert, FilePermission, FolderPermission, ProtectedFolder, Role
from .core_files import (
    accessible_folders, attempt_copy, list_files, permission_for, read_file,
    safe_file_path,
)
from .security import clear_failed_attempts, is_rate_limited, record_failed_attempt, secure_login_required
from .filesystem import InvalidProtectedPath, app_write_bytes, file_disk_path, folder_disk_path
from pathlib import Path
import mimetypes


User = get_user_model()
logger = logging.getLogger(__name__)

EMAIL_OTP_LIFETIME_SECONDS = 5 * 60
EMAIL_OTP_RESEND_COOLDOWN_SECONDS = 60
EMAIL_OTP_MAX_SENDS = 5


def _email_otp_digest(request, user, code):
    message = f"{user.pk}:{request.session.session_key}:{code}".encode("utf-8")
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _email_otp_cache_key(user):
    return f"sentrytrace:mfa-email-otp:{user.pk}"


def _email_otp_rate_key(user, action):
    return f"sentrytrace:mfa-email-{action}:{user.pk}"


def _email_otp_limited(user, action):
    return (cache.get(_email_otp_rate_key(user, action), 0) or 0) >= 5


def _record_email_otp_attempt(user, action):
    key = _email_otp_rate_key(user, action)
    if not cache.add(key, 1, timeout=5 * 60):
        try:
            cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=5 * 60)


def _send_email_otp(request, user):
    """Send an OTP without retaining its plaintext in the session or logs."""
    now = int(time.time())
    sent_at = int(request.session.get("mfa_email_otp_sent_at", 0))
    send_count = int(request.session.get("mfa_email_otp_send_count", 0))
    if sent_at and now - sent_at < EMAIL_OTP_RESEND_COOLDOWN_SECONDS:
        return "cooldown"
    if (send_count >= EMAIL_OTP_MAX_SENDS or is_rate_limited(request, user.username, "mfa_email_send")
            or _email_otp_limited(user, "sends")):
        return "limited"
    if not user.email:
        return "unavailable"
    if (settings.EMAIL_BACKEND == "django.core.mail.backends.smtp.EmailBackend"
            and not settings.EMAIL_HOST):
        return "not_configured"

    code = f"{secrets.randbelow(1_000_000):06d}"
    # A newly generated code invalidates any still-live code for this account,
    # including one issued to another session.
    cache.delete(_email_otp_cache_key(user))
    try:
        sent = send_mail(
            "Your SentryTrace verification code",
            f"Your SentryTrace verification code is {code}. It expires in five minutes and can only be used once.",
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
    except Exception as exc:
        # Do not log message content, recipient details, or the OTP.
        logger.warning("Email OTP delivery failed (exception type: %s).", type(exc).__name__)
        return "delivery_failed"
    if not sent:
        return "delivery_failed"

    # A successful resend replaces the only valid challenge.
    cache.set(_email_otp_cache_key(user), {
        "digest": _email_otp_digest(request, user, code),
        "session_key": request.session.session_key,
    }, timeout=EMAIL_OTP_LIFETIME_SECONDS)
    request.session["mfa_email_otp_expires_at"] = now + EMAIL_OTP_LIFETIME_SECONDS
    request.session["mfa_email_otp_sent_at"] = now
    request.session["mfa_email_otp_send_count"] = send_count + 1
    _record_email_otp_attempt(user, "sends")
    record_failed_attempt(request, user.username, "mfa_email_send")
    return "sent"


def _email_send_error(result):
    if result == "not_configured":
        return "Email OTP is not configured. Set SENTRYTRACE_EMAIL_HOST and SMTP settings, then restart SentryTrace."
    if result == "delivery_failed":
        return "Email delivery failed. Check the SMTP host, port, credentials, and TLS settings, then request a new code."
    if result == "unavailable":
        return "No registered email address is available for this account. Contact an administrator."
    if result == "limited":
        return "Email verification requests are temporarily limited. Try again later."
    if result == "cooldown":
        return "Please wait one minute before requesting another code."
    return "We could not send a verification code. Check the SMTP configuration and try again."


def _clear_email_otp(request, *, clear_pending=True):
    user = getattr(request, "user", None)
    if user is not None and getattr(user, "is_authenticated", False):
        cache.delete(_email_otp_cache_key(user))
    keys = ["mfa_email_otp_expires_at", "mfa_email_otp_sent_at", "mfa_email_otp_send_count"]
    if clear_pending:
        keys.append("mfa_pending_method")
    for key in keys:
        request.session.pop(key, None)


def _masked_email(email):
    local, separator, domain = email.partition("@")
    if not separator:
        return "your registered email address"
    return f"{local[:1]}***@{domain}"


def _complete_mfa(request, user, *, enrolled=False):
    if enrolled:
        user.mfa_enabled = True
        user.save(update_fields=["mfa_enabled"])
    request.session["mfa_verified"] = True
    clear_failed_attempts(request, user.username, "mfa")
    request.session.set_expiry(900)
    record_auth_event("mfa_enrolled" if enrolled else "mfa_verified", request, user)
    record_auth_event("login_success", request, user)
    if timezone.localtime().hour < 6 or timezone.localtime().hour >= 20:
        record_alert_event("off_hours_login", request, user=user, alert_type="off_hours_login", severity="medium")
    return redirect("admin_dashboard" if is_admin(user) else "dashboard")


# --------------------------------------------------
# USER ROLE CHECK
# --------------------------------------------------

def is_admin(user):
    return (
        user.is_authenticated
        and user.role is not None
        and user.role.role_name.lower() == "administrator"
    )


def visible_folders_for(user):
    return accessible_folders(user)


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            record_alert_event("admin_access_denied", request, details=f"Anonymous request to {request.path}",
                               alert_type="admin_access_denied", severity="high", outcome="BLOCKED")
            from django.contrib.auth.views import redirect_to_login
            return redirect_to_login(request.get_full_path())
        if not is_admin(request.user):
            record_alert_event("admin_access_denied", request, user=request.user,
                               details=f"Denied path: {request.path}",
                               alert_type="admin_access_denied", severity="high", outcome="BLOCKED")
            return HttpResponseForbidden("Administrator access required.")
        return view_func(request, *args, **kwargs)
    return wrapped


# --------------------------------------------------
# USER REGISTRATION
# --------------------------------------------------

def register_view(request):
    """Register new staff accounts."""

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        full_name = request.POST.get("full_name", "").strip()
        staff_id = request.POST.get("staff_id", "").strip()
        department = request.POST.get("department", "").strip()
        password = request.POST.get("password", "")
        password_confirm = request.POST.get("password_confirm", "")

        context = {
            "username": username,
            "email": email,
            "full_name": full_name,
            "staff_id": staff_id,
            "department": department,
        }

        if not all([username, email, full_name, staff_id, password]):
            context["error"] = "Please fill in all required fields."
            return render(request, "authentication/register.html", context)

        if password != password_confirm:
            context["error"] = "The password confirmation does not match."
            return render(request, "authentication/register.html", context)

        try:
            validate_password(password)
        except ValidationError as exc:
            context["error"] = " ".join(exc.messages)
            return render(request, "authentication/register.html", context)

        if User.objects.filter(username=username).exists():
            context["error"] = "Username already exists."
            return render(request, "authentication/register.html", context)

        if User.objects.filter(email__iexact=email).exists():
            context["error"] = "Email already registered."
            return render(request, "authentication/register.html", context)

        if User.objects.filter(staff_id=staff_id).exists():
            context["error"] = "Staff ID already registered."
            return render(request, "authentication/register.html", context)

        User.objects.create_user(
            username=username,
            email=email,
            full_name=full_name,
            staff_id=staff_id,
            password=password,
            department=department or None,
            status="pending",
        )

        messages.success(
            request,
            "Registration successful! Awaiting administrator approval."
        )

        return redirect("login")

    return render(request, "authentication/register.html")


# --------------------------------------------------
# USER LOGIN
# --------------------------------------------------

def login_view(request):
    """Authenticate users and redirect according to MFA and role."""

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        if is_rate_limited(request, username):
            record_auth_event("login_rate_limited", request, details=f"Username: {username}", outcome="BLOCKED")
            return render(request, "authentication/login.html", {
                "error": "Too many failed sign-in attempts. Try again in five minutes."
            }, status=429)

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:

            if user.status != "active":
                if user.status in {"on_leave", "suspended"}:
                    record_alert_event("login_denied_status", request, user=user,
                                       details=f"Account status: {user.status}",
                                       alert_type="on_leave_login" if user.status == "on_leave" else "suspended_login",
                                       severity="high", outcome="BLOCKED")
                else:
                    record_auth_event("login_denied", request, user, f"Account status: {user.status}", outcome="BLOCKED")
                record_failed_attempt(request, username)
                return render(
                    request,
                    "authentication/login.html",
                    {
                        "error": "Your account is not active. Contact the administrator."
                    }
                )

            login(request, user)
            request.session.cycle_key()
            request.session.set_expiry(900)
            _clear_email_otp(request)
            request.session["mfa_verified"] = False
            record_auth_event("login_password_accepted", request, user)
            clear_failed_attempts(request, username)
            if user.mfa_enabled and user.mfa_method == "email":
                result = _send_email_otp(request, user)
                if result != "sent":
                    messages.error(request, _email_send_error(result))
            return redirect("mfa_verify")

        record_auth_event("login_denied", request, None, f"Username: {username}", outcome="BLOCKED")
        record_failed_attempt(request, username)
        return render(
            request,
            "authentication/login.html",
            {"error": "Invalid username or password."}
        )

    return render(request, "authentication/login.html")


# --------------------------------------------------
# USER LOGOUT
# --------------------------------------------------

def logout_view(request):
    if request.method != "POST":
        return HttpResponseForbidden("Logout requires a POST request.")
    if request.user.is_authenticated:
        record_auth_event("logout", request, request.user)
    logout(request)
    return redirect("login")


# --------------------------------------------------
# MULTI-FACTOR AUTHENTICATION
# --------------------------------------------------

@login_required
def mfa_verify_view(request):
    user = request.user
    limiter_name = user.username
    email_challenge_account = (user.mfa_method == "email" or
                               request.session.get("mfa_pending_method") == "email")
    mfa_limited = request.method == "POST" and (
        is_rate_limited(request, limiter_name, "mfa") or
        (email_challenge_account and _email_otp_limited(user, "failures"))
    )
    if mfa_limited:
        record_auth_event("mfa_rate_limited", request, user, outcome="BLOCKED")
        messages.error(request, "Too many invalid codes. Try again in five minutes.")
        context = {"verification_only": True, "email_otp_pending": user.mfa_method == "email" or
                   request.session.get("mfa_pending_method") == "email", "email_hint": _masked_email(user.email)}
        return render(request, "authentication/mfa_verify.html", context, status=429)

    # Let an already verified user change their preferred method from this existing security screen.
    if request.session.get("mfa_verified") and request.method == "POST" and request.POST.get("change_mfa_method"):
        selected_method = request.POST.get("mfa_method")
        if selected_method not in {"authenticator", "email"}:
            messages.error(request, "Choose a valid MFA method.")
        elif selected_method == "email":
            if not user.email:
                messages.error(request, "A registered email address is required for email verification.")
            else:
                request.session["mfa_verified"] = False
                request.session["mfa_pending_method"] = "email"
                _clear_email_otp(request)
                request.session["mfa_pending_method"] = "email"
                result = _send_email_otp(request, user)
                if result == "sent":
                    messages.success(request, "A verification code was sent to your registered email address.")
                else:
                    messages.error(request, _email_send_error(result))
        elif user.totp_secret:
            _clear_email_otp(request)
            user.mfa_method = "authenticator"
            user.save(update_fields=["mfa_method"])
            messages.success(request, "Google Authenticator is now your preferred MFA method.")
        else:
            _clear_email_otp(request)
            user.mfa_method = "authenticator"
            user.mfa_enabled = False
            user.save(update_fields=["mfa_method", "mfa_enabled"])
            request.session["mfa_verified"] = False
            request.session.pop("mfa_enrollment_secret", None)
            messages.info(request, "Set up Google Authenticator to finish changing your MFA method.")

    email_pending = (user.mfa_method == "email" and not request.session.get("mfa_verified")) or \
                    request.session.get("mfa_pending_method") == "email"
    if email_pending:
        if request.method == "POST" and request.POST.get("resend_email_otp"):
            result = _send_email_otp(request, user)
            if result == "sent":
                messages.success(request, "A new verification code was sent.")
            elif result == "limited":
                record_auth_event("mfa_email_send_limited", request, user, outcome="BLOCKED")
            else:
                if result in {"not_configured", "delivery_failed", "unavailable"}:
                    record_auth_event("mfa_email_delivery_failed", request, user, outcome="BLOCKED")
            if result != "sent":
                messages.error(request, _email_send_error(result))
        elif request.method == "POST" and request.POST.get("verification_code"):
            code = request.POST.get("verification_code", "").strip()
            challenge = cache.get(_email_otp_cache_key(user)) or {}
            expected = challenge.get("digest", "") if challenge.get("session_key") == request.session.session_key else ""
            expires_at = int(request.session.get("mfa_email_otp_expires_at", 0))
            supplied = _email_otp_digest(request, user, code) if len(code) == 6 and code.isdigit() else ""
            if expected and int(time.time()) < expires_at and hmac.compare_digest(expected, supplied):
                pending_method = request.session.get("mfa_pending_method")
                if pending_method == "email":
                    user.mfa_method = "email"
                    user.mfa_enabled = True
                    user.save(update_fields=["mfa_method", "mfa_enabled"])
                _clear_email_otp(request)
                if user.status != "active":
                    logout(request)
                    return redirect("login")
                cache.delete(_email_otp_rate_key(user, "failures"))
                return _complete_mfa(request, user, enrolled=pending_method == "email")
            record_auth_event("mfa_email_denied", request, user, outcome="BLOCKED")
            _record_email_otp_attempt(user, "failures")
            record_failed_attempt(request, limiter_name, "mfa")
            if expected and int(time.time()) >= expires_at:
                _clear_email_otp(request, clear_pending=False)
            messages.error(request, "Invalid or expired verification code. Request a new code and try again.")
        return render(request, "authentication/mfa_verify.html", {
            "verification_only": True,
            "email_otp_pending": True,
            "email_hint": _masked_email(user.email),
            "allow_method_change": bool(request.session.get("mfa_verified")),
            "current_method": user.mfa_method,
        })

    if user.mfa_enabled:
        if request.method == "POST":
            code = request.POST.get("verification_code", "").strip()
            if user.totp_secret and pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
                if user.status != "active":
                    logout(request)
                    return redirect("login")
                return _complete_mfa(request, user)
            record_auth_event("mfa_denied", request, user, outcome="BLOCKED")
            record_failed_attempt(request, limiter_name, "mfa")
            messages.error(request, "Invalid verification code. Please try again.")
        return render(request, "authentication/mfa_verify.html", {
            "verification_only": True,
            "current_method": user.mfa_method,
            "allow_method_change": request.session.get("mfa_verified", False),
            "already_verified": request.session.get("mfa_verified", False),
        })

    if request.method == "POST" and request.POST.get("mfa_method") == "email":
        request.session["mfa_pending_method"] = "email"
        result = _send_email_otp(request, user)
        if result == "sent":
            messages.success(request, "A verification code was sent to your registered email address.")
        elif result == "limited":
            record_auth_event("mfa_email_send_limited", request, user, outcome="BLOCKED")
        else:
            record_auth_event("mfa_email_delivery_failed", request, user, outcome="BLOCKED")
        if result != "sent":
            messages.error(request, _email_send_error(result))
        return render(request, "authentication/mfa_verify.html", {
            "verification_only": True, "email_otp_pending": True,
            "email_hint": _masked_email(user.email),
        })

    if not request.session.get("mfa_enrollment_secret"):
        request.session["mfa_enrollment_secret"] = user.totp_secret or pyotp.random_base32()
    enrollment_secret = request.session["mfa_enrollment_secret"]
    totp = pyotp.TOTP(enrollment_secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name="SentryTrace")
    qr = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_image = base64.b64encode(buffer.getvalue()).decode("utf-8")

    if request.method == "POST":
        verification_code = request.POST.get("verification_code", "").strip()
        if totp.verify(verification_code, valid_window=1):
            user.totp_secret = enrollment_secret
            user.mfa_method = "authenticator"
            user.mfa_enabled = True
            user.save(update_fields=["totp_secret", "mfa_method", "mfa_enabled"])
            request.session.pop("mfa_enrollment_secret", None)
            return _complete_mfa(request, user, enrolled=True)
        record_auth_event("mfa_enrollment_denied", request, user, outcome="BLOCKED")
        record_failed_attempt(request, limiter_name, "mfa")
        messages.error(request, "Invalid verification code. Please try again.")

    return render(request, "authentication/mfa_verify.html", {
        "qr_image": qr_image,
        "secret_key": enrollment_secret,
        "enrollment": True,
        "current_method": user.mfa_method,
    })


# --------------------------------------------------
# USER DASHBOARD
# --------------------------------------------------

@login_required
def dashboard_view(request):

    if is_admin(request.user):
        return redirect("admin_dashboard")

    if request.user.role_id and request.user.role.role_name.lower() == "auditor":
        from .models import AccessLog
        return render(request, "dashboards/auditor_dashboard.html", {
            "recent_events": AccessLog.objects.order_by("-event_time")[:10],
            "event_count": AccessLog.objects.count(),
        })
    return render(request, "authentication/user_dashboard.html", {
        "visible_folders": visible_folders_for(request.user),
    })


# --------------------------------------------------
# ADMINISTRATOR DASHBOARD
# --------------------------------------------------

@admin_required
def admin_dashboard_view(request):

    pending_count = User.objects.filter(status="pending").count()
    active_count = User.objects.filter(status="active").count()
    from .models import AccessLog
    from django.contrib.sessions.models import Session
    active_sessions = sum(bool(session.get_decoded().get("_auth_user_id")) for session in Session.objects.filter(expire_date__gt=timezone.now()).iterator())
    today = timezone.localdate()
    alerts = Alert.objects.filter(status="open").select_related("log", "log__user").order_by("-created_at")
    rows = [
        {"e": event, "status": event.outcome}
        for event in AccessLog.objects.select_related("user").order_by("-log_id")[:50]
    ]
    recent_auth_events = AccessLog.objects.filter(
        event_type__in=("login_success", "login_denied", "mfa_denied", "mfa_email_denied")
    ).select_related("user").order_by("-event_time")[:5]
    integrity = verify_integrity()

    return render(
        request,
        "authentication/admin_dashboard.html",
        {
            "pending_count": pending_count,
            "active_count": active_count,
            "recent_events": AccessLog.objects.select_related("user").order_by("-event_time")[:6],
            "event_count": AccessLog.objects.filter(event_time__date=today).count(),
            "active_sessions": active_sessions,
            "open_alerts": Alert.objects.filter(status="open").count(),
            "folders_count": ProtectedFolder.objects.count(),
            "chain_ok": integrity["valid"],
            "high_alerts": alerts.filter(severity="high").count(),
            "medium_alerts": alerts.filter(severity="medium").count(),
            "low_alerts": alerts.filter(severity="low").count(),
            "role_counts": Role.objects.annotate(user_count=Count("user")).values("role_name", "user_count"),
            "rows": rows,
            "alerts": alerts,
            "recent_auth_events": recent_auth_events,
        }
    )


# --------------------------------------------------
# PENDING USERS
# --------------------------------------------------

@admin_required
def pending_users_view(request):

    if request.method == "POST":
        name = request.POST.get("role_name", "").strip()
        description = request.POST.get("description", "").strip()
        if not name:
            messages.error(request, "Enter a role name.")
        elif len(name) > 50:
            messages.error(request, "Role names must be 50 characters or fewer.")
        elif Role.objects.filter(role_name__iexact=name).exists():
            messages.error(request, "A role with that name already exists.")
        else:
            role = Role.objects.create(role_name=name, description=description or None)
            record_auth_event("role_created", request, request.user,
                             f"Role: {role.role_name}")
            messages.success(request, f"Role ‘{role.role_name}’ is ready to assign.")
        return redirect("pending_users")

    pending_users = User.objects.filter(
        status="pending"
    ).order_by("created_at")

    return render(request, "authentication/users.html", {
        "pending_users": pending_users,
        "users": User.objects.select_related("role").order_by("full_name"),
        "roles": Role.objects.order_by("role_name"),
    })


# --------------------------------------------------
# APPROVE USER
# --------------------------------------------------

@admin_required
@require_POST
def approve_user_view(request, user_id):

    user = get_object_or_404(
        User,
        user_id=user_id,
        status="pending"
    )

    role = get_object_or_404(Role, pk=request.POST.get("role_id"))

    user.status = "active"
    user.role = role
    user.save(update_fields=["status", "role"])
    record_auth_event("registration_approved", request, request.user, f"User id: {user.user_id}; role: {role.role_name}")

    messages.success(
        request,
        f"{user.full_name}'s account has been approved."
    )

    return redirect("pending_users")


# --------------------------------------------------
# REJECT USER
# --------------------------------------------------

@admin_required
@require_POST
def reject_user_view(request, user_id):

    user = get_object_or_404(
        User,
        user_id=user_id,
        status="pending"
    )

    user.status = "rejected"
    user.save(update_fields=["status"])
    record_auth_event("registration_rejected", request, request.user, f"User id: {user.user_id}")

    messages.success(
        request,
        f"{user.full_name}'s registration was rejected."
    )

    return redirect("pending_users")


@admin_required
@require_POST
def update_user_status_view(request, user_id):
    user = get_object_or_404(User, user_id=user_id)
    status = request.POST.get("status")
    if status not in {"active", "on_leave", "suspended", "rejected"}:
        messages.error(request, "Choose a valid account status.")
        return redirect("pending_users")
    if user == request.user and status != "active":
        messages.error(request, "You cannot disable your own administrator account.")
        return redirect("pending_users")
    old_status = user.status
    role_id = request.POST.get("role_id")
    if role_id:
        user.role = get_object_or_404(Role, pk=role_id)
    if status == "active" and not (role_id or user.role_id):
        messages.error(request, "Assign a role before activating this account.")
        return redirect("pending_users")
    user.status = status
    fields = ["status"] + (["role"] if role_id else [])
    user.save(update_fields=fields)
    record_auth_event("account_status_changed", request, request.user, f"User id: {user.user_id}; {old_status} -> {status}")
    messages.success(request, f"{user.full_name}'s status is now {status}.")
    return redirect("pending_users")


@admin_required
@require_POST
def delete_user(request, pk):
    user = get_object_or_404(User, pk=pk)
    if user.pk == request.user.pk:
        messages.error(request, "You cannot delete your own administrator account.")
    elif user.username == "system":
        messages.error(request, "The system account cannot be deleted.")
    else:
        username = user.username
        user.delete()
        messages.success(request, f"User account '{username}' was deleted.")
    return redirect("pending_users")


# --------------------------------------------------
# FOLDER ACCESS
# --------------------------------------------------

@secure_login_required
def folder_access_view(request):
    if is_admin(request.user):
        visible_folders = ProtectedFolder.objects.all().order_by("project_name")
        file_permissions = [{"permission": item, "view": True, "edit": True, "copy": True}
                            for item in FilePermission.objects.select_related("folder").all()]
    elif request.user.role_id:
        visible_folders = visible_folders_for(request.user)
        file_permissions = []
        for item in FilePermission.objects.filter(role=request.user.role).select_related("folder"):
            actions = {action: file_action_allowed(request.user, item.folder, item.file_path, action)[0]
                       for action in ("view", "edit", "copy")}
            if any(actions.values()):
                file_permissions.append({"permission": item, **actions})
    else:
        visible_folders = ProtectedFolder.objects.none()
        file_permissions = []
    folder_access_rows = [
        {"folder": folder, "permission": permission_for(request.user, folder)}
        for folder in visible_folders
    ]
    return render(
        request,
        "authentication/folder_access.html",
        {"visible_folders": visible_folders, "folder_access_rows": folder_access_rows,
         "file_permissions": file_permissions,
         "user_role": request.user.role.role_name if request.user.role_id else "Unassigned"}
    )


@admin_required
def admin_access_management_view(request):
    from .filesystem import InvalidProtectedPath, clean_relative_path, file_disk_path, folder_disk_path
    if request.method == "POST":
        action = request.POST.get("action")
        try:
            role = get_object_or_404(Role, pk=request.POST.get("role_id")) if action in {"folder_acl", "file_acl"} else None
            if action == "create_folder":
                relative = clean_relative_path(request.POST.get("folder_path", ""))
                project_name = request.POST.get("project_name", "").strip()
                if not project_name:
                    raise InvalidProtectedPath("Project name is required.")
                if len(project_name) > 100:
                    raise InvalidProtectedPath("Project name must be 100 characters or fewer.")
                # Resolve and create the real directory under the configured protected root.
                folder_path = folder_disk_path(ProtectedFolder(folder_path=relative, project_name=project_name))
                folder_path.mkdir(parents=True, exist_ok=True)
                folder, created = ProtectedFolder.objects.get_or_create(
                    folder_path=relative,
                    defaults={"project_name": project_name, "owner": request.user},
                )
            elif action == "folder_acl":
                folder = get_object_or_404(ProtectedFolder, pk=request.POST.get("folder_id"))
                FolderPermission.objects.update_or_create(role=role, folder=folder, defaults={
                    "can_view": request.POST.get("can_view") == "on",
                    "can_edit": request.POST.get("can_edit") == "on",
                    "can_copy": request.POST.get("can_copy") == "on",
                })
            elif action == "folder_acl_grid":
                folder = get_object_or_404(ProtectedFolder, pk=request.POST.get("folder_id"))
                for grid_role in Role.objects.exclude(role_name__iexact="administrator"):
                    prefix = f"role_{grid_role.pk}_"
                    FolderPermission.objects.update_or_create(role=grid_role, folder=folder, defaults={
                        "can_view": request.POST.get(prefix + "can_view") == "on",
                        "can_edit": request.POST.get(prefix + "can_edit") == "on",
                        "can_copy": request.POST.get(prefix + "can_copy") == "on",
                    })
            elif action == "file_acl":
                folder = get_object_or_404(ProtectedFolder, pk=request.POST.get("folder_id"))
                relative = clean_relative_path(request.POST.get("file_path", ""))
                uploaded = request.FILES.get("upload")
                if uploaded:
                    disk_file = file_disk_path(folder, relative)
                    if uploaded.size > 10_000_000:
                        raise InvalidProtectedPath("Uploads are limited to 10 MB.")
                    from .filesystem import app_write_bytes
                    app_write_bytes(disk_file, uploaded.read())
                else:
                    disk_file = file_disk_path(folder, relative, must_exist=True)
                if not disk_file.is_file():
                    raise InvalidProtectedPath("Select a file inside the protected folder.")
                FilePermission.objects.update_or_create(role=role, folder=folder, file_path=relative, defaults={
                    "can_view": request.POST.get("can_view") == "on",
                    "can_edit": request.POST.get("can_edit") == "on",
                    "can_copy": request.POST.get("can_copy") == "on",
                })
            else:
                return HttpResponse("Unknown access management action.", status=400)
            record_auth_event("access_policy_updated", request, request.user, f"Action: {action}")
            messages.success(request, "Access policy saved.")
        except (InvalidProtectedPath, OSError) as exc:
            messages.error(request, str(exc))
        redirect_name = "manage_folders" if request.resolver_match.url_name == "manage_folders" else "admin_access_management"
        return redirect(redirect_name)
    roles = list(Role.objects.exclude(role_name__iexact="administrator").order_by("role_name"))
    folders = list(ProtectedFolder.objects.all().order_by("project_name"))
    folder_acl_grids = []
    for folder in folders:
        permissions = {item.role_id: item for item in FolderPermission.objects.filter(folder=folder)}
        folder_acl_grids.append({
            "folder": folder,
            "roles": [{"role": role, "permission": permissions.get(role.pk)} for role in roles],
        })
    return render(request, "authentication/access_management.html", {
        "roles": Role.objects.order_by("role_name"),
        "folders": folders,
        "folder_acl_grids": folder_acl_grids,
        "folder_permissions": FolderPermission.objects.select_related("role", "folder"),
        "file_permissions": FilePermission.objects.select_related("role", "folder"),
    })


# --------------------------------------------------
# PERFORM FOLDER ACTION
# --------------------------------------------------

@secure_login_required
def perform_folder_action_view(request, folder_id, action):
    folder = ProtectedFolder.objects.filter(folder_id=folder_id).first()
    if not folder:
        record_alert_event("folder_access_denied", request, user=request.user,
                           details=f"Unknown folder id {folder_id}", alert_type="unauthorized_access",
                           severity="high", outcome="BLOCKED", path=f"folder:{folder_id}")
        return HttpResponse("Protected folder not found.", status=404)
    if action not in {"view", "edit", "copy"}:
        record_file_event(request, folder, action, "DENIED")
        return HttpResponseForbidden("Unsupported folder action.")
    if action != "view":
        if action == "copy":
            record_alert_event("copy_denied", request, user=request.user, details=f"Folder copy operation unsupported: {folder.folder_path}",
                               alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                               folder=folder, path=folder.folder_path)
        else:
            record_file_event(request, folder, action, "DENIED")
        return HttpResponse("Choose a specific file for edit or copy operations.", status=400)
    folder_acl = FolderPermission.objects.filter(folder=folder, role=request.user.role).first() if request.user.role_id else None
    file_acl_rows = FilePermission.objects.filter(folder=folder, role=request.user.role) if request.user.role_id else FilePermission.objects.none()
    allowed = is_admin(request.user) or bool(
        (folder_acl and folder_acl.can_view) or
        (not folder_acl and file_acl_rows.filter(can_view=True).exists())
    )
    if not allowed:
        record_file_event(request, folder, action, "DENIED")
        return HttpResponseForbidden("You do not have permission for this folder action.")
    record_file_event(request, folder, action, "OK")
    try:
        disk_folder = folder_disk_path(folder, must_exist=True)
    except (InvalidProtectedPath, OSError):
        return HttpResponse("Protected folder is missing or invalid.", status=404)
    filename = request.GET.get("filename")
    if filename:
        selected_path = safe_file_path(folder, filename)
        if selected_path is None or not selected_path.is_file():
            record_alert_event("path_traversal_denied", request, user=request.user,
                               details="Unsafe filename supplied in protected-folder request.",
                               alert_type="unauthorized_access", severity="high", outcome="BLOCKED",
                               folder=folder, path=f"{folder.folder_path}/{str(filename)[:450]}")
        else:
            file_allowed, _ = file_action_allowed(request.user, folder, filename, "view")
            if not file_allowed:
                record_file_event(request, folder, "view", "DENIED", f"{folder.folder_path}/{filename}")
                return HttpResponseForbidden("You do not have permission to view this file.")
            return _handle_protected_file_action(request, folder_id, filename, "view")
    files = []
    for relative in list_files(folder):
        path = safe_file_path(folder, relative)
        if path is None or not path.is_file():
            continue
        allowed_view, _ = file_action_allowed(request.user, folder, relative, "view")
        if allowed_view and path.is_file():
            files.append({
                "path": relative,
                "can_edit": file_action_allowed(request.user, folder, relative, "edit")[0],
                "can_copy": file_action_allowed(request.user, folder, relative, "copy")[0],
            })
    return render(request, "authentication/folder_files.html", {
        "folder": folder, "files": files, "selected": None,
    })


@secure_login_required
def folder_detail_view(request, pk):
    """Named folder-detail route kept alongside the original folder_action URL."""
    return perform_folder_action_view(request, pk, "view")


def file_action_allowed(user, folder, relative_path, action):
    if is_admin(user):
        return True, None
    if not user.role_id:
        return False, None
    file_acl = FilePermission.objects.filter(role=user.role, folder=folder, file_path=relative_path).first()
    folder_acl = FolderPermission.objects.filter(role=user.role, folder=folder).first()
    if folder_acl and not getattr(folder_acl, f"can_{action}"):
        return False, file_acl or folder_acl
    if file_acl and not getattr(file_acl, f"can_{action}"):
        return False, file_acl
    if file_acl and getattr(file_acl, f"can_{action}"):
        return True, file_acl
    if folder_acl and getattr(folder_acl, f"can_{action}"):
        return True, folder_acl
    return False, file_acl or folder_acl


def protected_file_view(request, folder_id, relative_path):
    action = request.POST.get("action", "") if request.method == "POST" else request.GET.get("action", "view")
    return _handle_protected_file_action(request, folder_id, relative_path, action)


@secure_login_required
def perform_file_action_view(request, folder_id, file_permission_id, action):
    folder = ProtectedFolder.objects.filter(folder_id=folder_id).first()
    if not folder:
        record_alert_event("file_access_denied", request, user=request.user,
                           details=f"Unknown folder id {folder_id}; ACL {file_permission_id}",
                           alert_type="unauthorized_access", severity="high", outcome="BLOCKED",
                           path=f"folder:{folder_id}/permission:{file_permission_id}")
        return HttpResponse("Protected folder not found.", status=404)
    file_permission = FilePermission.objects.filter(
        permission_id=file_permission_id, folder=folder
    ).first()
    relative_path = file_permission.file_path if file_permission else f"missing-permission-{file_permission_id}"
    return _handle_protected_file_action(request, folder_id, relative_path, action)


@secure_login_required
def protected_file_path_view(request, folder_id, relative_path):
    return protected_file_view(request, folder_id, relative_path)


def _handle_protected_file_action(request, folder_id, relative_path, action):
    folder = ProtectedFolder.objects.filter(folder_id=folder_id).first()
    if not folder:
        record_alert_event("file_access_denied", request, user=request.user,
                           details=f"Unknown folder id {folder_id}", alert_type="unauthorized_access",
                           severity="high", outcome="BLOCKED", path=f"folder:{folder_id}/{relative_path[:450]}")
        return HttpResponse("Protected folder not found.", status=404)
    if action not in {"view", "edit", "copy"}:
        record_file_event(request, folder, action, "DENIED", f"{folder.folder_path}/{relative_path}")
        return HttpResponseForbidden("Unsupported file action.")
    target_path = f"{folder.folder_path}/{relative_path}"
    allowed, source_permission = file_action_allowed(request.user, folder, relative_path, action)
    if not allowed:
        if action == "copy":
            record_alert_event("copy_denied", request, user=request.user, details=f"Copy denied: {target_path}",
                               alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                               folder=folder, path=target_path)
        else:
            record_file_event(request, folder, action, "DENIED", target_path)
        return HttpResponseForbidden("You do not have permission for this file action.")
    source_path = safe_file_path(folder, relative_path)
    if source_path is None or not source_path.is_file():
        record_file_event(request, folder, action, "DENIED", target_path)
        return HttpResponseForbidden("Invalid file path.")

    if action == "view":
        try:
            with source_path.open("r", encoding="utf-8") as stream:
                stream.read(1)
            content = read_file(source_path)
            record_file_event(request, folder, "view", "OK", target_path)
            return render(request, "authentication/file_detail.html", {
                "folder": folder, "relative_path": relative_path, "content": content,
                "content_truncated": source_path.stat().st_size > 20_000,
                "can_edit": file_action_allowed(request.user, folder, relative_path, "edit")[0],
                "can_copy": file_action_allowed(request.user, folder, relative_path, "copy")[0],
            })
        except UnicodeDecodeError:
            pass
        record_file_event(request, folder, "view", "OK", target_path)
        content_type = mimetypes.guess_type(source_path.name)[0] or "application/octet-stream"
        return FileResponse(source_path.open("rb"), as_attachment=True, filename=source_path.name,
                            content_type=content_type)

    if action == "edit":
        if request.method == "GET":
            try:
                content = source_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                return HttpResponse("Only UTF-8 text files can be edited in the browser.", status=415)
            return render(request, "authentication/file_edit.html", {"folder": folder, "relative_path": relative_path, "content": content})
        if request.method != "POST":
            return HttpResponseNotAllowed(["GET", "POST"])
        content = request.POST.get("content", "")
        if len(content.encode("utf-8")) > 2_000_000:
            return HttpResponse("File exceeds the 2 MB edit limit.", status=413)
        app_write_bytes(source_path, content.encode("utf-8"))
        record_file_event(request, folder, "edit", "OK", target_path)
        messages.success(request, f"Updated {relative_path}.")
        return redirect("folder_action", folder_id=folder.pk, action="view")

    if action == "copy":
        if request.method == "GET":
            destination_folders = ProtectedFolder.objects.filter(
                folderpermission__role=request.user.role, folderpermission__can_edit=True
            ).distinct() if request.user.role_id else ProtectedFolder.objects.none()
            if is_admin(request.user):
                destination_folders = ProtectedFolder.objects.all()
            return render(request, "authentication/file_copy.html", {
                "folder": folder, "relative_path": relative_path, "destination_folders": destination_folders,
            })
        if request.method != "POST":
            return HttpResponseNotAllowed(["GET", "POST"])
        destination = ProtectedFolder.objects.filter(folder_id=request.POST.get("destination_folder_id")).first()
        if not destination:
            record_alert_event("copy_denied", request, user=request.user, details="Unknown destination folder.",
                               alert_type="unauthorized_copy", severity="high", outcome="BLOCKED",
                               folder=folder, path=target_path)
            return HttpResponseForbidden("Destination folder does not exist.")
        requested_name = request.POST.get("destination_file_path", "").strip() or None
        success, message = attempt_copy(request.user, folder, source_permission, source_path,
                                        destination, request.META.get("REMOTE_ADDR"), requested_name)
        if not success:
            return HttpResponseForbidden(message)
        messages.success(request, message)
        return redirect("folder_action", folder_id=folder.pk, action="view")
