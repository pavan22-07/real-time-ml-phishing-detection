"""
Views handling URL scan submissions, scan history retrieval, and dashboard metrics.
"""

from datetime import timedelta
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.throttling import ScopedRateThrottle

from .models import ScanHistory
from .permissions import IsScanOwner
from .serializers import (
    ScanRequestSerializer,
    ScanResponseSerializer,
    DashboardStatsSerializer,
)
from .services import execute_url_scan


class ScanCreateListView(generics.ListCreateAPIView):
    """
    POST /api/v1/scans/ - Submit a URL for unified phishing detection.
    GET  /api/v1/scans/ - Retrieve paginated scan history for authenticated user.
    """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ScanResponseSerializer
    throttle_classes = (ScopedRateThrottle,)
    throttle_scope = "scans"

    def get_queryset(self):
        """Users can access only their own scan records, ordered by newest first."""
        return ScanHistory.objects.filter(user=self.request.user).order_by("-created_at")

    def create(self, request, *args, **kwargs):
        serializer = ScanRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        url = serializer.validated_data["url"]

        scan_record, _ = execute_url_scan(url, user=request.user)
        response_serializer = ScanResponseSerializer(scan_record)

        return Response(response_serializer.data, status=status.HTTP_201_CREATED)


class ScanDetailView(generics.RetrieveAPIView):
    """
    GET /api/v1/scans/{id}/ - Retrieve a single scan record by UUID.
    Guarantees strict per-user isolation (404 if record belongs to another user).
    """
    permission_classes = (permissions.IsAuthenticated, IsScanOwner)
    serializer_class = ScanResponseSerializer
    lookup_field = "id"

    def get_queryset(self):
        return ScanHistory.objects.filter(user=self.request.user)


class DashboardStatsView(APIView):
    """
    GET /api/v1/dashboard/stats/ - Aggregate statistics for the authenticated user.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user_scans = ScanHistory.objects.filter(user=request.user)

        total_scans = user_scans.count()
        total_allow = user_scans.filter(final_decision="ALLOW").count()
        total_warn = user_scans.filter(final_decision="WARN").count()
        total_block = user_scans.filter(final_decision="BLOCK").count()
        total_error = user_scans.filter(final_decision="ERROR").count()

        # Count scans created within the last 24 hours as recent
        recent_cutoff = timezone.now() - timedelta(hours=24)
        recent_scans_count = user_scans.filter(created_at__gte=recent_cutoff).count()

        latest_scan = user_scans.order_by("-created_at").first()
        latest_scan_timestamp = latest_scan.created_at if latest_scan else None

        stats_data = {
            "total_scans": total_scans,
            "total_allow": total_allow,
            "total_warn": total_warn,
            "total_block": total_block,
            "total_error": total_error,
            "recent_scans_count": recent_scans_count,
            "latest_scan_timestamp": latest_scan_timestamp,
        }

        serializer = DashboardStatsSerializer(stats_data)
        return Response(serializer.data, status=status.HTTP_200_OK)
