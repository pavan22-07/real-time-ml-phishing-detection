"""
URL routing for scans application.
"""

from django.urls import path
from .views import ScanCreateListView, ScanDetailView

urlpatterns = [
    path("", ScanCreateListView.as_view(), name="scan-list-create"),
    path("<uuid:id>/", ScanDetailView.as_view(), name="scan-detail"),
]
