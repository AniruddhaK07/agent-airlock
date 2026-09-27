"""
Circuit Breaker package for Jev Airlock.
"""

from agent_airlock.circuit_breaker.hasher import (
    ErrorSignature,
    normalize_error,
    normalize_command,
    compute_similarity,
)
from agent_airlock.circuit_breaker.breaker import (
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
