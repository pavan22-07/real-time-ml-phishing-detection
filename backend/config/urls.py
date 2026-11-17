"""
URL configuration for the Phishing Detection & Prevention System.
"""

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/v1/auth/", include("accounts.urls")),
    path("api/v1/scans/", include("scans.urls")),
    path("api/v1/dashboard/", include("scans.dashboard_urls")),
]
