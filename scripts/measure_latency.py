"""
Accurate latency measurement for in-process Laya model inference.
Enforces explicit CUDA stream synchronization (torch.cuda.synchronize())
before and after inference to measure real end-to-end device completion time.
Computes p50, p90, p95, p99, mean, min, max.
"""

import time
import numpy as np
import torch
import os
import sys
from pathlib import Path

repo_root = str(Path(__file__).parent.parent.resolve())
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from agent_airlock.jev.local_laya import LocalLayaClient, QUESTIONS

def benchmark_inference(num_iterations=100):
    print("=" * 70)
    print("REAL IN-PROCESS LAYA INFERENCE LATENCY BENCHMARK")
    print("=" * 70)

    device_name = torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU"
    print(f"Device: {device_name}")
    print(f"CUDA Available: {torch.cuda.is_available()}")

    # 1. Measure Model Load Time
    t0_load = time.perf_counter()
    client = LocalLayaClient()
    t1_load = time.perf_counter()
    print(f"Model Load / Initialization Time: {(t1_load - t0_load)*1000:.2f} ms")

    commands = [
        "ls -la",
        "rm -rf /tmp/test",
        "git log -n 5",
        "npm install express",
        "docker ps -a",
        "python scripts/build.py",
        "cat package.json",
        "kill -9 1234",
    ]

    # 2. Cold Start (First Inference)
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    t0_cold = time.perf_counter()
    _ = client.evaluate_ambiguous_tool("run_command", {"CommandLine": "python manage.py runserver"})
    if torch.cuda.is_available():
        torch.cuda.synchronize()
    t1_cold = time.perf_counter()
    cold_ms = (t1_cold - t0_cold) * 1000.0
    print(f"Cold Start (1st inference with CUDA sync): {cold_ms:.2f} ms")

    # 3. Warmup (10 runs)
    print("Running 10 warmup iterations...")
    for i in range(10):
        cmd = commands[i % len(commands)]
        _ = client.evaluate_ambiguous_tool("run_command", {"CommandLine": cmd})
    if torch.cuda.is_available():
        torch.cuda.synchronize()

    # 4. Synchronized GPU Latency Benchmark (Actual GPU completion)
    sync_latencies = []
    async_dispatch_latencies = []

    print(f"Executing {num_iterations} synchronized benchmark iterations...")
    for i in range(num_iterations):
        cmd = commands[i % len(commands)]

        # Synchronized timing (REAL GPU COMPLETION)
        if torch.cuda.is_available():
            torch.cuda.synchronize()
        t0_sync = time.perf_counter()

        _ = client.evaluate_ambiguous_tool("run_command", {"CommandLine": cmd})

        if torch.cuda.is_available():
            torch.cuda.synchronize()
        t1_sync = time.perf_counter()

        sync_latencies.append((t1_sync - t0_sync) * 1000.0)

    # 5. Measure without sync (CPU queue dispatch only) to demonstrate the contrast
    print(f"Executing {num_iterations} asynchronous dispatch iterations (no cuda sync)...")
    for i in range(num_iterations):
        cmd = commands[i % len(commands)]
        t0_async = time.perf_counter()
        _ = client.evaluate_ambiguous_tool("run_command", {"CommandLine": cmd})
        t1_async = time.perf_counter()
        async_dispatch_latencies.append((t1_async - t0_async) * 1000.0)
    if torch.cuda.is_available():
        torch.cuda.synchronize()

    sync_arr = np.array(sync_latencies)
    async_arr = np.array(async_dispatch_latencies)

    print("\n" + "=" * 70)
    print("LATENCY RESULTS SUMMARY (N = %d runs)" % num_iterations)
    print("=" * 70)
    print("REAL GPU-SYNCHRONIZED LATENCY (torch.cuda.synchronize()):")
    print(f"  p50 (Median) : {np.percentile(sync_arr, 50):6.2f} ms")
    print(f"  p90          : {np.percentile(sync_arr, 90):6.2f} ms")
    print(f"  p95          : {np.percentile(sync_arr, 95):6.2f} ms")
    print(f"  p99          : {np.percentile(sync_arr, 99):6.2f} ms")
    print(f"  Mean +/- Std : {np.mean(sync_arr):6.2f} +/- {np.std(sync_arr):.2f} ms")
    print(f"  Min / Max    : {np.min(sync_arr):6.2f} ms / {np.max(sync_arr):6.2f} ms")

    print("\nASYNC DISPATCH-ONLY LATENCY (NO cuda sync - illusionary timing):")
    print(f"  p50 (Median) : {np.percentile(async_arr, 50):6.2f} ms")
    print(f"  p95          : {np.percentile(async_arr, 95):6.2f} ms")
    print(f"  Mean         : {np.mean(async_arr):6.2f} ms")
    print("=" * 70)

    return {
        "sync_p50": float(np.percentile(sync_arr, 50)),
        "sync_p90": float(np.percentile(sync_arr, 90)),
        "sync_p95": float(np.percentile(sync_arr, 95)),
        "sync_p99": float(np.percentile(sync_arr, 99)),
        "sync_mean": float(np.mean(sync_arr)),
        "cold_start_ms": cold_ms,
    }

if __name__ == "__main__":
    benchmark_inference(100)
