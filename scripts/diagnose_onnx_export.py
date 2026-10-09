"""
Diagnostic tool to test ONNX export feasibility for the fine-tuned ModernBERT / Laya model.
Checks:
1. Model structure and forward signature
2. TorchScript / ONNX tracing with sample input tensors
3. Op compatibility (flash-attn, rotary, custom heads)
"""

import os
import sys
from pathlib import Path
import torch

os.environ["USE_TF"] = "0"
import laya
import laya.common

from agent_airlock.backends.laya import DEFAULT_CHECKPOINT, QUESTIONS


def diagnose():
    print("=" * 80)
    print("DIAGNOSING ONNX EXPORT FEASIBILITY FOR FINE-TUNED LAYA MODEL")
    print("=" * 80)

    if not Path(DEFAULT_CHECKPOINT).exists():
        print(f"Error: Checkpoint path does not exist: {DEFAULT_CHECKPOINT}")
        return

    print(f"Loading model directly from {DEFAULT_CHECKPOINT} on CPU...")
    agent = laya.load(DEFAULT_CHECKPOINT, device="cpu")
    model = agent.model
    tok = agent.tok
    model.eval()

    print(f"Model class: {type(model).__name__} ({type(model).__module__})")
    print(f"Encoder: {type(getattr(model, 'encoder', None)).__name__}")
    
    # Encode a sample command
    q_ids = ["blast_radius", "reversible", "route"]
    internal_q = {qid: agent._to_internal(QUESTIONS[qid]) for qid in q_ids}
    sample_state = {"tool": "run_command", "command": "git push --force origin main"}
    
    items = agent._encode_state(sample_state, q_ids, internal_q)
    b = laya.common.collate_items([items], tok.pad_token_id)
    
    input_ids = b["input_ids"]
    attention_mask = b["attention_mask"]
    marker_pos = b["marker_pos"]
    marker_mask = b["marker_mask"]
    qtype = b["qtype"]

    print("\nSample input tensor shapes:")
    print(f"  input_ids     : {input_ids.shape} ({input_ids.dtype})")
    print(f"  attention_mask: {attention_mask.shape} ({attention_mask.dtype})")
    print(f"  marker_pos    : {marker_pos.shape} ({marker_pos.dtype})")
    print(f"  marker_mask   : {marker_mask.shape} ({marker_mask.dtype})")
    print(f"  qtype         : {qtype.shape} ({qtype.dtype})")

    # Native forward pass
    with torch.no_grad():
        logits, act_logits = model(input_ids, attention_mask, marker_pos, marker_mask, qtype)
    print(f"\nNative forward pass successful!")
    print(f"  logits shape: {logits.shape}, act_logits shape: {act_logits.shape if act_logits is not None else None}")

    # Test ONNX Export
    onnx_out_path = Path("scratch_model.onnx")
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
    }

    print("\nAttempting torch.onnx.export (opset=17)...")
    try:
        torch.onnx.export(
            model,
            args,
            str(onnx_out_path),
            input_names=input_names,
            output_names=output_names,
            dynamic_axes=dynamic_axes,
            opset_version=17,
            do_constant_folding=True,
        )
        file_size_mb = onnx_out_path.stat().st_size / (1024 * 1024)
        print(f"[SUCCESS] ONNX export succeeded! Output file: {onnx_out_path} ({file_size_mb:.2f} MB)")
        # Clean up scratch onnx file
        if onnx_out_path.exists():
            onnx_out_path.unlink()
            print("Cleaned up scratch ONNX file.")
    except Exception as e:
        print(f"[FAIL] ONNX export failed with exception:\n{type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    diagnose()
