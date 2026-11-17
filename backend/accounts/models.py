"""
Accounts models.
Uses Django's built-in User model for authentication and access control.
"""

from django.contrib.auth.models import User

# Using Django's built-in User model
__all__ = ["User"]
