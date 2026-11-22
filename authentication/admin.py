from django.contrib import admin
from .models import User, Role, ProtectedFolder, FolderPermission, FilePermission, AccessLog, Alert, Report

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'full_name', 'staff_id', 'role', 'status')
    search_fields = ('username', 'email', 'staff_id', 'full_name')
    list_filter = ('status', 'role', 'department')

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ('role_id', 'role_name', 'description')

@admin.register(ProtectedFolder)
class ProtectedFolderAdmin(admin.ModelAdmin):
    list_display = ('project_name', 'folder_path', 'owner')

@admin.register(FolderPermission)
class FolderPermissionAdmin(admin.ModelAdmin):
    list_display = ('role', 'folder', 'can_view', 'can_edit', 'can_copy')

@admin.register(FilePermission)
class FilePermissionAdmin(admin.ModelAdmin):
    list_display = ('role', 'folder', 'file_path', 'can_view', 'can_edit', 'can_copy')
    list_filter = ('role', 'folder', 'can_view', 'can_edit', 'can_copy')
    search_fields = ('file_path', 'folder__project_name', 'role__role_name')

@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'user', 'event_type', 'file_path', 'event_time', 'ip_address', 'outcome')
    list_filter = ('outcome', 'event_type', 'event_time')
    search_fields = ('event_type', 'file_path', 'details', 'user__username')
    readonly_fields = tuple(field.name for field in AccessLog._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_type', 'severity', 'status', 'created_at')
    list_filter = ('alert_type', 'severity', 'status')
    readonly_fields = ('log', 'alert_type', 'severity', 'created_at')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('generated_by', 'date_from', 'date_to', 'department', 'created_at')
