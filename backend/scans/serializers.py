"""
Serializers for scan requests, responses, and historical audit records.
"""

from rest_framework import serializers
from .models import ScanHistory


class ScanRequestSerializer(serializers.Serializer):
    """Serializer validating incoming URL scan submissions."""
    url = serializers.CharField(
        max_length=2048,
        required=True,
        allow_blank=False,
        trim_whitespace=True,
        help_text="Target URL to be analyzed."
    )

    def validate_url(self, value):
        url_val = value.strip()
        if not url_val:
            raise serializers.ValidationError("URL cannot be empty or blank.")
        if len(url_val) > 2048:
            raise serializers.ValidationError("URL exceeds maximum permitted length of 2048 characters.")
        return url_val


class CybersecuritySummarySerializer(serializers.Serializer):
    """Cybersecurity engine signal summary."""
    status = serializers.CharField(allow_null=True)
    verdict = serializers.CharField(allow_null=True)
    risk_score = serializers.IntegerField(allow_null=True)


class MachineLearningSummarySerializer(serializers.Serializer):
    """Machine learning engine signal summary."""
    status = serializers.CharField(allow_null=True)
    prediction = serializers.CharField(allow_null=True)
    raw_phishing_probability = serializers.FloatField(allow_null=True)
    is_calibrated = serializers.BooleanField(default=False)


class ScanResponseSerializer(serializers.ModelSerializer):
    """
    Structured scan output serializer strictly conforming to Section 8 specification.
    """
    cybersecurity = serializers.SerializerMethodField()
    machine_learning = serializers.SerializerMethodField()
    reasons = serializers.ListField(source="scan_reasons", read_only=True)
    warnings = serializers.ListField(read_only=True)
    timestamp = serializers.DateTimeField(source="created_at", format="iso-8601", read_only=True)

    class Meta:
        model = ScanHistory
        fields = (
            "id",
            "url",
            "final_decision",
            "degraded_mode",
            "cybersecurity",
            "machine_learning",
            "reasons",
            "warnings",
            "timestamp",
        )
        read_only_fields = fields

    def get_cybersecurity(self, obj):
        eng_statuses = obj.engine_statuses or {}
        status_val = (
            eng_statuses.get("security_engine")
            or eng_statuses.get("cybersecurity", "UNKNOWN")
        )
        return {
            "status": status_val,
            "verdict": obj.cybersecurity_verdict,
            "risk_score": obj.cybersecurity_risk_score,
        }

    def get_machine_learning(self, obj):
        eng_statuses = obj.engine_statuses or {}
        status_val = (
            eng_statuses.get("ml_engine")
            or eng_statuses.get("machine_learning", "UNKNOWN")
        )
        # Ensure is_calibrated is explicitly false
        return {
            "status": status_val,
            "prediction": obj.ml_prediction,
            "raw_phishing_probability": obj.raw_phishing_probability,
            "is_calibrated": False,
        }


class DashboardStatsSerializer(serializers.Serializer):
    """Dashboard metrics and aggregate scan statistics."""
    total_scans = serializers.IntegerField()
    total_allow = serializers.IntegerField()
    total_warn = serializers.IntegerField()
    total_block = serializers.IntegerField()
    total_error = serializers.IntegerField()
    recent_scans_count = serializers.IntegerField()
    latest_scan_timestamp = serializers.DateTimeField(allow_null=True)
