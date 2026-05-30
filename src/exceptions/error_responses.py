"""Structured API error response builders."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from .base_exceptions import AegisException
from .error_codes import ErrorCode


def utc_timestamp() -> str:
    """Return an ISO-8601 UTC timestamp with Z suffix."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_error_payload(
    *,
    code: Union[ErrorCode, str],
    type_name: str,
    message: str,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the standardized nested error response body."""
    code_value = code.value if isinstance(code, ErrorCode) else str(code)
    payload: Dict[str, Any] = {
        "error": {
            "code": code_value,
            "type": type_name,
            "message": message,
            "request_id": request_id,
            "timestamp": timestamp or utc_timestamp(),
            "details": details or {},
        }
    }
    return payload


def build_error_from_aegis_exception(
    exc: AegisException,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    return build_error_payload(
        code=exc.code,
        type_name=exc.type_name,
        message=exc.message,
        request_id=request_id,
        details=exc.details,
    )


def build_validation_error_payload(
    *,
    field: str,
    value: Any,
    constraint: str,
    suggestion: str,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a validation error response for a single field."""
    return build_error_payload(
        code="VALIDATION_ERROR",
        type_name="ValidationError",
        message=f"Validation failed for field '{field}'",
        request_id=request_id,
        details={
            "field": field,
            "value": str(value) if not isinstance(value, (str, int, float, bool)) else value,
            "constraint": constraint,
            "suggestion": suggestion,
        },
    )


def build_multi_field_validation_error_payload(
    *,
    errors: list[Dict[str, Any]],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a validation error response for multiple fields."""
    return build_error_payload(
        code="VALIDATION_ERROR",
        type_name="ValidationError",
        message="Validation failed for multiple fields",
        request_id=request_id,
        details={
            "field_errors": errors,
        },
    )


def build_rate_limit_error_payload(
    *,
    retry_after_seconds: int,
    limit_type: str = "account",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a rate limit error response."""
    return build_error_payload(
        code="RATE_LIMIT_EXCEEDED",
        type_name="RateLimitError",
        message=f"Rate limit exceeded for {limit_type}",
        request_id=request_id,
        details={
            "limit_type": limit_type,
            "retry_after_seconds": retry_after_seconds,
        },
    )


def build_pydantic_validation_errors(
    *,
    errors: list[Dict[str, Any]],
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an error response from Pydantic validation errors."""
    formatted_errors = []
    for error in errors:
        loc = error.get("loc", ())
        msg = error.get("msg", "Validation error")
        formatted_errors.append({
            "field": ".".join(str(l) for l in loc) if loc else "unknown",
            "message": msg,
        })
    
    return build_error_payload(
        code="VALIDATION_ERROR",
        type_name="ValidationError",
        message=f"Validation failed: {len(formatted_errors)} error(s)",
        request_id=request_id,
        details={
            "field_errors": formatted_errors,
        },
    )
