from django.shortcuts import redirect
from django.http import HttpResponseForbidden
from django.urls import reverse
from django.contrib.auth import logout
from audit_logs.services import record_alert_event


class MFARequiredMiddleware:
    """Keep authenticated sessions on the MFA enrollment/verification gate."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if request.path.startswith("/admin/"):
            if not user.is_authenticated:
                record_alert_event("admin_access_denied", request, details=f"Anonymous admin request to {request.path}",
                                   alert_type="admin_access_denied", severity="high", outcome="BLOCKED")
                return redirect("login")
            if not (user.role_id and user.role.role_name.lower() == "administrator"):
                record_alert_event("admin_access_denied", request, user=user,
                                   details=f"Denied path: {request.path}",
                                   alert_type="admin_access_denied", severity="high", outcome="BLOCKED")
                return HttpResponseForbidden("Administrator access required.")
        if user.is_authenticated:
            if user.status != "active":
                alert_type = "on_leave_login" if user.status == "on_leave" else "suspended_login"
                record_alert_event("session_revoked_status", request, user=user,
                                   details=f"Active session ended because account status is {user.status}.",
                                   alert_type=alert_type, severity="high", outcome="BLOCKED")
                logout(request)
                return redirect("login")
            allowed = {
                reverse("mfa_verify"),
                reverse("logout"),
            }
            if not user.mfa_enabled or not request.session.get("mfa_verified"):
                if request.path not in allowed:
                    record_alert_event("mfa_gate_access_blocked", request, user=user,
                                       details=f"Attempted path before MFA: {request.path}",
                                       alert_type="unauthorized_access", severity="high", outcome="BLOCKED")
                    return redirect("mfa_verify")
        return self.get_response(request)
