
from authentication import views
from django.urls import path

urlpatterns = [
    # Authentication
    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("mfa/verify/", views.mfa_verify_view, name="mfa_verify"),

    # Staff dashboard
    path("dashboard/", views.dashboard_view, name="dashboard"),

    # Administrator dashboard
    path("admin-dashboard/", views.admin_dashboard_view, name="admin_dashboard"),
    path("admin/users/", views.pending_users_view, name="pending_users"),
    path(
        "admin/users/<int:user_id>/approve/",
        views.approve_user_view,
        name="approve_user",
    ),
    path(
        "admin/users/<int:user_id>/reject/",
        views.reject_user_view,
        name="reject_user",
    ),
    path("admin/users/<int:user_id>/status/", views.update_user_status_view, name="update_user_status"),
    path("manage/users/<int:pk>/delete/", views.delete_user, name="delete_user"),
    path("admin/access/", views.admin_access_management_view, name="admin_access_management"),
    path("manage/folders/", views.admin_access_management_view, name="manage_folders"),

    # Folder management
    path("folders/", views.folder_access_view, name="folder_access"),
    path("folders/", views.folder_access_view, name="folders"),
    path("folders/<int:pk>/", views.folder_detail_view, name="folder_detail"),
    path(
        "folders/<int:folder_id>/<str:action>/",
        views.perform_folder_action_view,
        name="folder_action",
    ),
    path(
        "folders/<int:folder_id>/files/<int:file_permission_id>/<str:action>/",
        views.perform_file_action_view,
        name="file_action",
    ),
    path("folders/<int:folder_id>/files/<path:relative_path>/", views.protected_file_path_view, name="protected_file"),
]
