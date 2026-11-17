"""
Custom REST framework exception handling.
Ensures safe error responses without leaking internal stack traces.
"""

import logging
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Handle exceptions raised in DRF views.
    Preserves DRF structured error formats while securing unhandled exceptions.
    """
    response = exception_handler(exc, context)

    if response is not None:
        # Standard DRF exception (e.g. ValidationError, PermissionDenied, NotAuthenticated)
        if isinstance(response.data, list):
            response.data = {"errors": response.data}
        elif isinstance(response.data, dict) and "detail" not in response.data and "error" not in response.data:
            # Wrap field-level validation errors
            pass
        return response

    # Unhandled server exception (e.g., unexpected database error)
    view = context.get("view")
    view_name = view.__class__.__name__ if view else "UnknownView"
    logger.error("Unhandled API exception in %s: %s", view_name, exc, exc_info=True)

    return Response(
        {
            "error": "Internal server error",
            "message": "An unexpected error occurred while processing your request. Please try again later."
        },
        status=status.HTTP_500_INTERNAL_SERVER_ERROR
    )
