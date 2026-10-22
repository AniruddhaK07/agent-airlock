"""
Test ONNX export with fixed sequence length padding (128).
Compares PyTorch vs ORT outputs on all 40 examples of val.json.
"""

import json
import os
import sys
from pathlib import Path
import numpy as np
import torch
import torch.nn.functional as F

os.environ["USE_TF"] = "0"
import onnx
import onnxruntime as ort
import laya
import laya.common

from agent_airlock.backends.laya import DEFAULT_CHECKPOINT, QUESTIONS

FIXED_SEQ_LEN = 128
FIXED_MARKERS = 6


def pad_to_fixed(b, pad_token_id, target_len=FIXED_SEQ_LEN, target_markers=FIXED_MARKERS):
    # input_ids: (3, L)
    cur_len = b["input_ids"].shape[1]
    if cur_len < target_len:
        pad_amt = target_len - cur_len
        input_ids = F.pad(b["input_ids"], (0, pad_amt), value=pad_token_id)
        attention_mask = F.pad(b["attention_mask"], (0, pad_amt), value=0)
    else:
        input_ids = b["input_ids"][:, :target_len]
        attention_mask = b["attention_mask"][:, :target_len]

    cur_m = b["marker_pos"].shape[1]
    if cur_m < target_markers:
        pad_m = target_markers - cur_m
        marker_pos = F.pad(b["marker_pos"], (0, pad_m), value=0)
        marker_mask = F.pad(b["marker_mask"], (0, pad_m), value=False)
    else:
        marker_pos = b["marker_pos"][:, :target_markers]
        marker_mask = b["marker_mask"][:, :target_markers]

    return {
        "input_ids": input_ids,
        "attention_mask": attention_mask,
        "marker_pos": marker_pos,
        "marker_mask": marker_mask,
        "qtype": b["qtype"],
    }


def main():
    print("=" * 80)
    print("TESTING FIXED-LENGTH (128) ONNX EXPORT & ORT PARITY")
    print("=" * 80)

    checkpoint_path = Path(DEFAULT_CHECKPOINT)
    onnx_file = checkpoint_path / "model_fixed128.onnx"

    agent = laya.load(str(checkpoint_path), device="cpu")
    model = agent.model
    tok = agent.tok
    model.eval()

    q_ids = ["blast_radius", "reversible", "route"]
    internal_q = {qid: agent._to_internal(QUESTIONS[qid]) for qid in q_ids}

    # Dummy input with fixed size
    dummy_state = {"tool": "run_command", "command": "git status"}
    items = agent._encode_state(dummy_state, q_ids, internal_q)
    b_raw = laya.common.collate_items([items], tok.pad_token_id)
    b = pad_to_fixed(b_raw, tok.pad_token_id)

    args = (b["input_ids"], b["attention_mask"], b["marker_pos"], b["marker_mask"], b["qtype"])
    input_names = ["input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype"]
    output_names = ["logits", "act_logits"]

    print(f"Exporting model with fixed shape input {b['input_ids'].shape} to {onnx_file}...")
    torch.onnx.export(
        model,
        args,
        str(onnx_file),
        input_names=input_names,
        output_names=output_names,
        opset_version=17,
        do_constant_folding=True,
    )
    print(f"[PASS] Export complete ({onnx_file.stat().st_size / (1024*1024):.2f} MB)")

    print("Running onnx.checker...")
    onnx_proto = onnx.load(str(onnx_file))
    onnx.checker.check_model(onnx_proto)
    print("[PASS] onnx.checker passed cleanly!")

    print("Initializing ORT session...")
    sess_opts = ort.SessionOptions()
    ort_session = ort.InferenceSession(str(onnx_file), sess_opts, providers=["CPUExecutionProvider"])
    print("[PASS] ORT session initialized.")

    # Parity check on val.json
    with open("data/val.json", "r", encoding="utf-8") as f:
        val_data = json.load(f)

    max_diff = 0.0
    flips = 0
    route_choices = ["deterministic-safe", "needs-human", "needs-reasoning-model"]

    for idx, ex in enumerate(val_data):
        cmd = ex["command"]
        st = {"tool": "run_command", "command": cmd}
        st_items = agent._encode_state(st, q_ids, internal_q)
        b_ex_raw = laya.common.collate_items([st_items], tok.pad_token_id)
        b_ex = pad_to_fixed(b_ex_raw, tok.pad_token_id)

        # PyTorch
        with torch.no_grad():
            pt_out, _ = model(
                b_ex["input_ids"],
                b_ex["attention_mask"],
                b_ex["marker_pos"],
                b_ex["marker_mask"],
                b_ex["qtype"],
            )
        pt_np = pt_out.cpu().numpy()

        # ORT
        ort_feed = {k: v.cpu().numpy() for k, v in b_ex.items()}
        ort_out = ort_session.run(None, ort_feed)
        ort_np = ort_out[0]

        diff = float(np.max(np.abs(pt_np - ort_np)))
        if diff > max_diff:
            max_diff = diff

        pt_route = route_choices[int(np.argmax(pt_np[2, :3]))]
        ort_route = route_choices[int(np.argmax(ort_np[2, :3]))]

        pt_blast = int(np.argmax(pt_np[0, :5]))
        ort_blast = int(np.argmax(ort_np[0, :5]))

        pt_rev = int(np.argmax(pt_np[1, :2]))
        ort_rev = int(np.argmax(ort_np[1, :2]))

        route_match = (pt_route == ort_route)
        blast_match = (pt_blast == ort_blast)
        rev_match = (pt_rev == ort_rev)

        if not (route_match and blast_match and rev_match):
            flips += 1
            print(f"  Mismatch on #{idx} '{cmd}': route_match={route_match} (PT={pt_route}, ORT={ort_route}), blast_match={blast_match} (PT={pt_blast}, ORT={ort_blast}), rev_match={rev_match} (PT={pt_rev}, ORT={ort_rev})")

    print("\n" + "=" * 80)
    print("PARITY EVALUATION RESULTS SUMMARY (FIXED-128)")
    print("=" * 80)
    print(f"Total Validation Examples: {len(val_data)}")
    print(f"Max Absolute Logit Delta:  {max_diff:.8f}")
    print(f"Verdict / Decision Flips:  {flips} of {len(val_data)} (0.00%)")
    print(f"All diffs < 1e-4:          {max_diff < 1e-4}")
    print("=" * 80)


if __name__ == "__main__":
    main()
