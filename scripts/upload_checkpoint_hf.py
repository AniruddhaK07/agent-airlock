"""
Uploads the local fine-tuned Laya checkpoint directly to Hugging Face Hub.
Uses absolute paths and hf-transfer acceleration.
"""
import os
import sys
import time
from pathlib import Path
from huggingface_hub import HfApi

# Enable Rust-based fast multi-threaded uploads
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "1"

REPO_ID = "ruddh/agent-airlock-laya"
CHECKPOINT_DIR = str(Path(__file__).resolve().parent.parent / "checkpoints" / "laya-finetuned")

print(f"[Upload] Target Repo: {REPO_ID}", flush=True)
print(f"[Upload] Checkpoint Dir: {CHECKPOINT_DIR}", flush=True)

if not os.path.exists(CHECKPOINT_DIR):
    print(f"[Upload Error] Checkpoint directory not found at {CHECKPOINT_DIR}", flush=True)
    sys.exit(1)

api = HfApi()

print(f"[Upload] Ensuring repo '{REPO_ID}' exists...", flush=True)
api.create_repo(REPO_ID, repo_type="model", exist_ok=True)

t0 = time.time()
print(f"[Upload] Starting upload_folder with hf-transfer...", flush=True)
commit = api.upload_folder(
    folder_path=CHECKPOINT_DIR,
    repo_id=REPO_ID,
    repo_type="model",
    commit_message="Upload fine-tuned Laya checkpoint (weights and configuration)",
)
elapsed = time.time() - t0
print(f"[Upload] Successfully completed in {elapsed:.2f}s!", flush=True)
print(f"[Upload] Commit URL: {commit}", flush=True)

# Verification
files = api.list_repo_files(REPO_ID, repo_type="model")
print(f"[Upload] Remote files count: {len(files)}", flush=True)
for f in sorted(files):
    print(f"  - {f}", flush=True)
