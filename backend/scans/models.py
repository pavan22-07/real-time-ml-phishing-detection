"""
Models for the URL scanning module.
Tracks scan history, per-engine signals, verdicts, and combined decisions.
"""

import uuid
from django.conf import settings
from django.db import models


class ScanHistory(models.Model):
    """
    Persistent audit record of every URL scan performed.
    Stores the unified decision along with isolated cybersecurity and ML signals.
    """
    DECISION_CHOICES = (
        ("ALLOW", "Allow"),
        ("WARN", "Warn"),
        ("BLOCK", "Block"),
        ("ERROR", "Error"),
    )

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique identifier for the scan record."
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scans",
        help_text="User who initiated the scan."
    )
    url = models.CharField(
        max_length=2048,
        help_text="Normalized or submitted target URL analyzed."
    )
    final_decision = models.CharField(
        max_length=16,
        choices=DECISION_CHOICES,
        db_index=True,
        help_text="Unified decision: ALLOW, WARN, BLOCK, or ERROR."
    )
    cybersecurity_verdict = models.CharField(
        max_length=32,
        null=True,
        blank=True,
        help_text="Cybersecurity rule verdict: BENIGN, SUSPICIOUS, MALICIOUS, etc."
    )
    cybersecurity_risk_score = models.IntegerField(
        null=True,
        blank=True,
        help_text="Deterministic cybersecurity risk score (0-100)."
    )
    ml_prediction = models.CharField(
        max_length=32,
        null=True,
        blank=True,
        help_text="ML engine prediction: LEGITIMATE, PHISHING, etc."
    )
    raw_phishing_probability = models.FloatField(
        null=True,
        blank=True,
        help_text="Raw uncalibrated ML phishing probability (0.0 to 1.0)."
    )
    degraded_mode = models.BooleanField(
        default=False,
        help_text="Indicates whether one of the engines failed or returned degraded."
    )
    engine_statuses = models.JSONField(
        default=dict,
        help_text="Per-engine operational statuses (OK, DEGRADED, ERROR)."
    )
    scan_reasons = models.JSONField(
        default=list,
        help_text="List of reasons explaining the final decision."
    )
    warnings = models.JSONField(
        default=list,
        help_text="Aggregated inspection warnings and partial verification alerts."
    )
    errors = models.JSONField(
        default=dict,
        help_text="Per-engine error details, if any."
    )
    complete_result = models.JSONField(
        default=dict,
        help_text="Full structured output dictionary returned by the Unified Engine."
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp when the scan was executed."
    )

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Scan History"
        verbose_name_plural = "Scan Histories"
        indexes = [
            models.Index(fields=["user", "-created_at"], name="scan_user_created_idx"),
            models.Index(fields=["final_decision"], name="scan_decision_idx"),
        ]

    def __str__(self):
        return f"Scan {self.id} [{self.final_decision}] - {self.url[:50]}"
