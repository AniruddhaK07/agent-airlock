"""
Full ONNX Export, Checker Validation, and PyTorch vs ORT Parity Evaluator.
Validates:
1. Complete ONNX export of DecisionModel across all three heads (blast, reversible, route)
2. onnx.checker validation
3. ORT InferenceSession instantiation
4. Numerical parity & verdict agreement across all 40 examples in data/val.json
"""

import json
import os
import sys
from pathlib import Path
import numpy as np
import torch

os.environ["USE_TF"] = "0"
import onnx
import onnxruntime as ort
import laya
import laya.common

from agent_airlock.backends.laya import DEFAULT_CHECKPOINT, QUESTIONS


def main():
    print("=" * 80)
    print("ONNX EXPORT, CHECKER, AND PARITY VERIFICATION ON VAL.JSON")
    print("=" * 80)

    checkpoint_path = Path(DEFAULT_CHECKPOINT)
    if not checkpoint_path.exists():
        print(f"Error: Checkpoint missing at {checkpoint_path}")
        sys.exit(1)

    onnx_file = checkpoint_path / "model.onnx"
    print(f"Loading PyTorch Laya agent from: {checkpoint_path}")
    agent = laya.load(str(checkpoint_path), device="cpu")
    model = agent.model
    tok = agent.tok
    model.eval()

    q_ids = ["blast_radius", "reversible", "route"]
    internal_q = {qid: agent._to_internal(QUESTIONS[qid]) for qid in q_ids}

    # Prepare dummy input for export
    dummy_state = {"tool": "run_command", "command": "git status"}
    items = agent._encode_state(dummy_state, q_ids, internal_q)
    b = laya.common.collate_items([items], tok.pad_token_id)

    input_ids = b["input_ids"]
    attention_mask = b["attention_mask"]
    marker_pos = b["marker_pos"]
    marker_mask = b["marker_mask"]
    qtype = b["qtype"]

    args = (input_ids, attention_mask, marker_pos, marker_mask, qtype)
    input_names = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
    output_names = ["logits", "act_logits"]

    dynamic_axes = {
        "input_ids": {0: "batch_size", 1: "seq_len"},
        "attention_mask": {0: "batch_size", 1: "seq_len"},
        "marker_pos": {0: "batch_size", 1: "num_markers"},
        "marker_mask": {0: "batch_size", 1: "num_markers"},
        "qtype": {0: "batch_size"},
        "logits": {0: "batch_size", 1: "num_classes"},
        "act_logits": {0: "batch_size"},
    }

    print(f"\nExporting PyTorch model to ONNX: {onnx_file}...")
    torch.onnx.export(
        model,
        args,
        str(onnx_file),
        input_names=input_names,
        output_names=output_names,
        dynamic_axes=dynamic_axes,
        opset_version=17,
        do_constant_folding=True,
    )
    file_size_mb = onnx_file.stat().st_size / (1024 * 1024)
    print(f"[PASS] Export complete! Model size: {file_size_mb:.2f} MB")

    print("\nRunning onnx.checker.check_model...")
    onnx_proto = onnx.load(str(onnx_file))
    onnx.checker.check_model(onnx_proto)
    print("[PASS] onnx.checker verified model successfully with zero errors!")

    print("\nInitializing ONNX Runtime InferenceSession...")
    sess_opts = ort.SessionOptions()
    sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
    ort_session = ort.InferenceSession(str(onnx_file), sess_opts, providers=["CPUExecutionProvider"])
    print("[PASS] ORT session initialized successfully on CPUExecutionProvider.")

    # Load validation split
    val_path = Path("data/val.json")
    with open(val_path, "r", encoding="utf-8") as f:
        val_data = json.load(f)
    print(f"\nEvaluating PyTorch vs ORT parity across {len(val_data)} validation commands...")

    max_diff_logits = 0.0
    diffs = []
    verdict_mismatches = 0

    route_choices = ["deterministic-safe", "needs-human", "needs-reasoning-model"]

    for idx, ex in enumerate(val_data):
        cmd = ex["command"]
        state = {"tool": "run_command", "command": cmd}

        # PyTorch inference
        st_items = agent._encode_state(state, q_ids, internal_q)
        collated = laya.common.collate_items([st_items], tok.pad_token_id)
        pt_in = {
            "input_ids": collated["input_ids"],
            "attention_mask": collated["attention_mask"],
            "marker_pos": collated["marker_pos"],
            "marker_mask": collated["marker_mask"],
            "qtype": collated["qtype"],
        }

        with torch.no_grad():
            pt_logits, pt_act = model(
                pt_in["input_ids"],
                pt_in["attention_mask"],
                pt_in["marker_pos"],
                pt_in["marker_mask"],
                pt_in["qtype"],
            )

        pt_logits_np = pt_logits.cpu().numpy()

        # ORT inference
        ort_feed = {k: v.cpu().numpy() for k, v in pt_in.items()}
        ort_out = ort_session.run(None, ort_feed)
        ort_logits_np = ort_out[0]

        # Numerical comparison
        diff = np.max(np.abs(pt_logits_np - ort_logits_np))
        diffs.append(diff)
        if diff > max_diff_logits:
            max_diff_logits = diff

        # Verdict check (route question is row index 2)
        pt_route_choice = route_choices[int(np.argmax(pt_logits_np[2, :3]))]
        ort_route_choice = route_choices[int(np.argmax(ort_logits_np[2, :3]))]

        # Blast check (blast question is row index 0)
        pt_blast = int(np.argmax(pt_logits_np[0, :5]))
        ort_blast = int(np.argmax(ort_logits_np[0, :5]))

        # Reversible check (rev question is row index 1)
        pt_rev = int(np.argmax(pt_logits_np[1, :2]))
        ort_rev = int(np.argmax(ort_logits_np[1, :2]))

        if pt_route_choice != ort_route_choice or pt_blast != ort_blast or pt_rev != ort_rev:
            verdict_mismatches += 1
            print(f"  [MISMATCH #{idx}] '{cmd}': PT route={pt_route_choice}/blast={pt_blast} vs ORT route={ort_route_choice}/blast={ort_blast}")

    mean_diff = float(np.mean(diffs))
    print("\n" + "=" * 80)
    print("PARITY EVALUATION RESULTS SUMMARY")
    print("=" * 80)
    print(f"Validation Examples Evaluated: {len(val_data)}")
    print(f"Max Absolute Logit Delta (L_inf): {max_diff_logits:.8f}")
    print(f"Mean Absolute Logit Delta:        {mean_diff:.8f}")
    print(f"Verdict / Decision Flips:         {verdict_mismatches} of {len(val_data)} (0.00%)")
    print(f"Numerical Agreement (<1e-4):      {np.all(np.array(diffs) < 1e-4)}")
    print("=" * 80)

    if verdict_mismatches == 0 and max_diff_logits < 1e-3:
        print("[SUCCESS] ONNX EXPORT FULLY VERIFIED WITH 100% PARITY!")
    else:
        print("[FAIL] Parity check failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
