"""
Permissions for scans application.
"""

from rest_framework.permissions import BasePermission


class IsScanOwner(BasePermission):
    """
    Object-level permission allowing only the owner of a scan to access it.
    """
    def has_object_permission(self, request, view, obj):
        return obj.user == request.user
