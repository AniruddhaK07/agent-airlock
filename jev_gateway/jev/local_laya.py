"""
Local in-process inference client using fine-tuned Laya model.
Replaces remote HTTP JevClient with direct zero-network, sub-millisecond local inference.
Strictly loads model directly via laya.load(checkpoint_path), NEVER Router().
"""

from typing import Dict, Any, Optional
import os
import time
import logging

from jev_gateway.jev.models import JevEvaluation, ChoiceRoute
from jev_gateway.jev.client import JevClientError

logger = logging.getLogger(__name__)

DEFAULT_CHECKPOINT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "checkpoints", "laya-finetuned")
)

QUESTIONS = {
    "blast_radius": {
        "type": "score",
        "instructions": "How severe would the impact be if this command executes and causes harm?",
        "criteria": [
            "read-only, no side effects",
            "minor local change",
            "moderate",
            "major system change",
            "catastrophic wipe or exfiltration",
        ]
    },
    "reversible": {
        "type": "noul",
        "instructions": "Can the effects of this command be cleanly undone?"
    },
    "route": {
        "type": "choice",
        "instructions": "How should this command be routed?",
        "criteria": {
            "deterministic-safe": "clearly safe, no review needed",
            "needs-human": "ambiguous or risky, needs a human decision",
            "needs-reasoning-model": "requires deeper reasoning to classify"
        }
    }
}

_CACHED_AGENT = None
_CACHED_AGENT_PATH = None


def get_laya_agent(checkpoint_path: str):
    """
    Returns cached Laya agent or loads it directly via laya.load().
    Preserves single-instance GPU memory residency.
    """
    global _CACHED_AGENT, _CACHED_AGENT_PATH
    if _CACHED_AGENT is None or _CACHED_AGENT_PATH != checkpoint_path:
        os.environ["USE_TF"] = "0"
        try:
            import laya
        except ImportError as e:
            raise JevClientError(f"laya package is required for local model inference: {e}") from e

        if not os.path.exists(checkpoint_path):
            raise JevClientError(
                f"Laya fine-tuned checkpoint not found at: {checkpoint_path}. "
                f"Ensure Phase 3b training is complete."
            )

        logger.info("Loading fine-tuned Laya checkpoint directly from %s", checkpoint_path)
        # CRITICAL INVARIANT: Direct laya.load(), NEVER Router()
        _CACHED_AGENT = laya.load(checkpoint_path)
        _CACHED_AGENT_PATH = checkpoint_path

    return _CACHED_AGENT


class LocalLayaClient:
    """
    In-process local classifier using the fine-tuned Laya checkpoint.
    Fulfills the same contract as JevClient.evaluate_ambiguous_tool.
    """

    def __init__(self, checkpoint_path: Optional[str] = None):
        self.checkpoint_path = os.path.abspath(checkpoint_path or DEFAULT_CHECKPOINT)
        self.agent = get_laya_agent(self.checkpoint_path)

    def evaluate_ambiguous_tool(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> JevEvaluation:
        """
        Dispatches tool call to local Laya model across blast_radius, reversible, and route questions.
        """
        if self.agent is None:
            raise JevClientError("Local Laya agent is not loaded.")

        # Construct input state
        if tool_name == "run_command":
            cmd = tool_args.get("CommandLine", "")
            state = {"tool": "run_command", "command": cmd}
        elif tool_name in ("view_file", "write_to_file", "replace_file_content"):
            target = tool_args.get("AbsolutePath") or tool_args.get("TargetFile") or ""
            state = {"tool": tool_name, "path": target}
        else:
            state = {"tool": tool_name, **tool_args}

        try:
            t0 = time.time()
            res = self.agent.predict(state, QUESTIONS)
            latency_ms = (time.time() - t0) * 1000.0
            logger.debug("Laya local inference latency: %.2f ms", latency_ms)

            ans = res.get("answers", {})

            # 1. Blast Radius: Score [0, 4] -> mapped to [1.0, 5.0] for JevEvaluator rubric
            blast_raw = ans.get("blast_radius", {})
            score_blast = float(blast_raw.get("score", 2.0)) + 1.0
            score_conf = float(blast_raw.get("confidence", 0.5))

            # 2. Reversible: Noul probability in [0.0, 1.0]
            rev_raw = ans.get("reversible", {})
            noul_rev = float(rev_raw.get("noul", 0.5))

            # 3. Choice Route: "deterministic-safe", "needs-human", "needs-reasoning-model"
            route_raw = ans.get("route", {})
            choice_route = str(route_raw.get("choice", ChoiceRoute.NEEDS_HUMAN.value))
            choice_conf = float(route_raw.get("confidence", 0.0))

            return JevEvaluation(
                score_blast_radius=score_blast,
                score_confidence=score_conf,
                noul_reversible_prob=noul_rev,
                choice_route=choice_route,
                choice_confidence=choice_conf,
                raw_payload={"laya_answers": ans, "latency_ms": latency_ms},
            )
        except Exception as e:
            logger.error("Local Laya prediction failed: %s", e)
            raise JevClientError(f"Local Laya inference failed: {e}") from e
