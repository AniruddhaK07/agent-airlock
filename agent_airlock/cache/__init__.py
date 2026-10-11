"""
Exact-Key Decision Cache package for Agent Airlock.
"""

from agent_airlock.cache.decision_cache import (
    DecisionCache,
    CachedDecision,
    DEFAULT_TRUST_ROOT_FILES,
)

__all__ = [
    "DecisionCache",
    "CachedDecision",
    "DEFAULT_TRUST_ROOT_FILES",
]
