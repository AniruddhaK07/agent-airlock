"""
Client wrapper for TypeSafe Jev API.
Strictly pinned to model `jev-1.13.0`. Dispatches Score, Noul, and Choice
evaluations in a single combined request with strict timeout handling.
"""

from typing import Dict, Any, Optional, Callable
import os
import json
import time
import socket
import urllib.request
import urllib.error
import logging

from agent_airlock.jev.models import JevEvaluation, ChoiceRoute
from agent_airlock.jev.prompts import format_jev_evaluation_prompt

logger = logging.getLogger(__name__)

PINNED_MODEL = "jev-1.13.0"


class JevClientError(Exception):
    """Base exception for Jev client errors."""
    pass


class JevTimeoutError(JevClientError):
    """Raised when request to Jev API exceeds timeout."""
    pass


class JevParseError(JevClientError):
    """Raised when Jev API response is malformed or invalid."""
    pass


class JevClient:
    """
    Client for dispatching evaluations to TypeSafe's Jev model.
    Guarantees pinned model identity (jev-1.13.0) and structured response parsing.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = PINNED_MODEL,
        base_url: str = "https://api.typesafe.ai/v1",
        timeout: float = 0.400,
        max_retries: int = 1,
        transport: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        if model != PINNED_MODEL:
            raise ValueError(
                f"Invalid model '{model}'. Jev Gateway strictly pins model to '{PINNED_MODEL}'. "
                f"Silent upgrades or substitutions are forbidden."
            )

        self.model = model
        self.api_key = api_key or os.getenv("TYPESAFE_API_KEY", "")
        self.base_url = base_url.rstrip("/")
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self.transport = transport

    def evaluate_ambiguous_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JevEvaluation:
        """
        Dispatches Score, Noul, and Choice questions in a single request to Jev.
        Raises JevClientError or subclasses on network/timeout/parse failures.
        """
        payload = format_jev_evaluation_prompt(
            tool_name=tool_name,
            tool_args=tool_args,
            context=context,
        )
        payload["model"] = self.model

        raw_response = self._dispatch_with_retries(payload)
        return self._parse_evaluation(raw_response)

    def _dispatch_with_retries(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches request, retrying up to max_retries on transient network errors.
        Enforces a strict wall-clock total deadline budget across all attempts.
        """
        deadline = time.time() + self.timeout
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            time_remaining = deadline - time.time()
            if time_remaining <= 0:
                raise JevTimeoutError(
                    f"Total Jev evaluation wall-clock budget ({self.timeout * 1000:.0f}ms) "
                    f"exceeded before attempt {attempt + 1}."
                )

            try:
                if self.transport is not None:
                    try:
                        return self.transport(payload, time_remaining)
                    except TypeError:
                        return self.transport(payload)
                return self._http_post(payload, timeout=time_remaining)
            except JevTimeoutError as e:
                logger.warning("Jev request timeout on attempt %d/%d: %s", attempt + 1, self.max_retries + 1, e)
                last_error = e
                if time.time() >= deadline or attempt == self.max_retries:
                    raise JevTimeoutError(
                        f"Total Jev evaluation wall-clock budget exceeded ({e})"
                    ) from e
            except (socket.timeout, TimeoutError) as e:
                logger.warning("Socket timeout on attempt %d/%d: %s", attempt + 1, self.max_retries + 1, e)
                last_error = e
                if time.time() >= deadline or attempt == self.max_retries:
                    raise JevTimeoutError(
                        f"Total Jev evaluation wall-clock budget exceeded ({e})"
                    ) from e
            except JevClientError as e:
                # Do not retry on client-level parse or authentication errors
                raise
            except Exception as e:
                logger.warning("Jev request error on attempt %d/%d: %s", attempt + 1, self.max_retries + 1, e)
                last_error = e
                if time.time() >= deadline or attempt == self.max_retries:
                    raise JevClientError(f"Jev request failed after {attempt + 1} attempts: {e}") from e

        if last_error:
            raise JevClientError(f"Jev request failed: {last_error}") from last_error
        raise JevClientError("Unknown Jev dispatch failure.")

    def _http_post(self, payload: Dict[str, Any], timeout: Optional[float] = None) -> Dict[str, Any]:
        """Performs HTTP POST request using urllib with wall-clock remaining timeout."""
        effective_timeout = timeout if timeout is not None else self.timeout
        if effective_timeout <= 0:
            raise JevTimeoutError(f"Request timeout budget exhausted ({effective_timeout:.3f}s)")

        endpoint = f"{self.base_url}/evaluate"
        data = json.dumps(payload).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"jev-gateway/{self.model}",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=effective_timeout) as response:
                status_code = response.getcode()
                response_body = response.read().decode("utf-8")

                if status_code != 200:
                    raise JevClientError(f"Jev API returned HTTP status {status_code}: {response_body}")

                try:
                    return json.loads(response_body)
                except Exception as e:
                    raise JevParseError(f"Failed to parse Jev API JSON response: {e}") from e

        except (socket.timeout, TimeoutError) as e:
            raise JevTimeoutError(f"Jev API request timed out after {effective_timeout:.3f}s: {e}") from e
        except (JevParseError, JevTimeoutError, JevClientError):
            raise
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8")
            except Exception:
                pass
            raise JevClientError(f"Jev API HTTP error {e.code} ({e.reason}): {error_body}") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, (socket.timeout, TimeoutError)):
                raise JevTimeoutError(f"Jev API request timed out: {e.reason}") from e
            raise JevClientError(f"Jev API connection failed: {e.reason}") from e
        except Exception as e:
            raise JevClientError(f"Unexpected Jev API transport error: {e}") from e

    def _parse_evaluation(self, response: Dict[str, Any]) -> JevEvaluation:
        """
        Parses and validates the raw API response into a typed JevEvaluation.
        Supports both nested results schema and flat schema.
        """
        if not isinstance(response, dict):
            raise JevParseError(f"Expected JSON object in Jev response, got {type(response).__name__}")

        # Check model identity in response if present
        resp_model = response.get("model")
        if resp_model and resp_model != self.model:
            raise JevParseError(f"Response model '{resp_model}' does not match pinned model '{self.model}'")

        try:
            # Handle nested results schema:
            # {"results": {"score": {"value": 2.0, "confidence": 0.95}, "noul": {...}, "choice": {...}}}
            if "results" in response and isinstance(response["results"], dict):
                res = response["results"]
                score_data = res.get("score", {})
                noul_data = res.get("noul", {})
                choice_data = res.get("choice", {})

                blast_radius = float(score_data.get("value", score_data.get("blast_radius", 0.0)))
                score_conf = float(score_data.get("confidence", 0.0))
                reversible_prob = float(noul_data.get("probability", noul_data.get("reversible_prob", 0.0)))
                choice_route = str(choice_data.get("selection", choice_data.get("route", "")))
                choice_conf = float(choice_data.get("confidence", 0.0))
            else:
                # Handle flat schema
                blast_radius = float(response["score_blast_radius"])
                score_conf = float(response.get("score_confidence", 1.0))
                reversible_prob = float(response["noul_reversible_prob"])
                choice_route = str(response["choice_route"])
                choice_conf = float(response.get("choice_confidence", 1.0))

            # Validate range bounds
            if not (1.0 <= blast_radius <= 5.0):
                raise ValueError(f"Blast radius {blast_radius} out of valid range [1.0, 5.0]")
            if not (0.0 <= score_conf <= 1.0):
                raise ValueError(f"Score confidence {score_conf} out of valid range [0.0, 1.0]")
            if not (0.0 <= reversible_prob <= 1.0):
                raise ValueError(f"Reversible probability {reversible_prob} out of valid range [0.0, 1.0]")
            if not (0.0 <= choice_conf <= 1.0):
                raise ValueError(f"Choice confidence {choice_conf} out of valid range [0.0, 1.0]")

            valid_routes = {
                ChoiceRoute.DETERMINISTIC_SAFE.value,
                ChoiceRoute.NEEDS_HUMAN.value,
                ChoiceRoute.NEEDS_REASONING_MODEL.value,
            }
            if choice_route not in valid_routes:
                raise ValueError(f"Choice route '{choice_route}' is not one of valid routes: {valid_routes}")

            return JevEvaluation(
                score_blast_radius=blast_radius,
                score_confidence=score_conf,
                noul_reversible_prob=reversible_prob,
                choice_route=choice_route,
                choice_confidence=choice_conf,
                raw_payload=response,
            )

        except (KeyError, ValueError, TypeError) as e:
            raise JevParseError(f"Failed to validate Jev evaluation fields: {e}") from e
