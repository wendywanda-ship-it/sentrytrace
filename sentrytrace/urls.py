"""
URL configuration for sentrytrace project.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('', include('authentication.urls')),
    path('', include('audit_logs.urls')),
    path('admin/', admin.site.urls),
]
