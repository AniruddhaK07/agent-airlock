"""
Circuit Breaker package for Jev Airlock.
"""

from jev_gateway.circuit_breaker.hasher import (
    ErrorSignature,
    normalize_error,
    normalize_command,
    compute_similarity,
)
from jev_gateway.circuit_breaker.breaker import (
    CircuitBreaker,
    CircuitBreakerResult,
)

__all__ = [
    "ErrorSignature",
    "normalize_error",
    "normalize_command",
    "compute_similarity",
    "CircuitBreaker",
    "CircuitBreakerResult",
]
