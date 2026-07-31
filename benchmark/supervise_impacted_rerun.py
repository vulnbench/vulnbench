"""Supervise the impacted-model VulnBench rerun without duplicating active jobs."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def safe_name(model: str) -> str:
    name = model.removeprefix("openrouter/")
    return name.replace("/", "_").replace(":", "_")


def parse_models(runner: Path) -> list[str]:
    text = runner.read_text()
    match = re.search(r"default_models=\(\s*(.*?)\n\)", text, re.S)
    if not match:
        raise SystemExit(f"Could not find default_models in {runner}")

    models: list[str] = []
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        models.append(line.strip("\"'"))
    return models


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = value.strip("\"'")
        values[key] = value
    return values


def is_complete(output: Path, benchmark: Path) -> bool:
    try:
        report = json.loads(output.read_text())
        bench = json.loads(benchmark.read_text())
    except Exception:
        return False

    expected = len(bench.get("instances", []))
    metadata = report.get("metadata", {})
    aggregate = report.get("aggregate", {})
    return (
        aggregate.get("total_instances") == expected
        and metadata.get("adapter_max_attempts", 0) >= 3
        and metadata.get("retry_empty_responses") is True
        and len(metadata.get("judge_models", [])) >= 2
    )


def active_models() -> dict[str, str]:
    proc = subprocess.run(
        ["ps", "-axo", "pid,ppid,stat,etime,command"],
        text=True,
        capture_output=True,
        check=False,
    )
    active: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if "-m benchmark.run_best_of_n" not in line or " --model " not in line:
            continue
        match = re.search(r"--model\s+(\S+)", line)
        if not match:
            continue
        parts = line.split(None, 4)
        pid = parts[0] if parts else "?"
        etime = parts[3] if len(parts) > 3 else "?"
        active[match.group(1)] = f"pid={pid} etime={etime}"
    return active


def aggregate_summary(output: Path) -> str:
    try:
        report = json.loads(output.read_text())
    except Exception as exc:
        return f"invalid_json={exc}"
    aggregate = report.get("aggregate", {})
    return (
        f"pass={aggregate.get('total_passed')}/"
        f"{aggregate.get('total_instances')} "
        f"rate={aggregate.get('pass_rate')} "
        f"score={aggregate.get('mean_score')}"
    )


def launch_model(
    model: str,
    args: argparse.Namespace,
    env: dict[str, str],
    attempt: int,
) -> subprocess.Popen[bytes]:
    output = args.output_dir / f"best{args.runs}_{safe_name(model)}.json"
    log_path = args.log_dir / f"{safe_name(model)}_attempt{attempt}.log"
    cmd = [
        str(args.python),
        "-m",
        "benchmark.run_best_of_n",
        "--benchmark",
        str(args.benchmark),
        "--model",
        model,
        "--runs",
        str(args.runs),
        "--max-tokens",
        str(args.max_tokens),
        "--adapter-max-attempts",
        str(args.adapter_max_attempts),
        "--adapter-retry-backoff-base-s",
        str(args.backoff_base_s),
        "--adapter-retry-backoff-max-s",
        str(args.backoff_max_s),
        "--adapter-retry-backoff-jitter-s",
        str(args.backoff_jitter_s),
        "--include-source",
        "--file-hint-mode",
        "description",
        "--judge-models",
        *args.judge_models,
        "--output",
        str(output),
    ]
    if args.reasoning_exclude:
        cmd.append("--reasoning-exclude")
    if args.reasoning_max_tokens:
        cmd.extend(["--reasoning-max-tokens", str(args.reasoning_max_tokens)])

    log = log_path.open("ab", buffering=0)
    header = (
        f"\n=== supervisor launch {time.strftime('%Y-%m-%d %H:%M:%S %Z')} "
        f"attempt={attempt} model={model} ===\n"
        f"cmd={shlex.join(cmd)}\n"
    )
    log.write(header.encode())
    proc = subprocess.Popen(
        cmd,
        cwd=ROOT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    proc._vulnbench_log = log  # type: ignore[attr-defined]
    return proc


def stop_pids(pids: list[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGSTOP)
            print(f"[PAUSE] pid={pid}", flush=True)
        except ProcessLookupError:
            pass


def resume_pids(pids: list[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGCONT)
            print(f"[RESUME] pid={pid}", flush=True)
        except ProcessLookupError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runner", type=Path, default=ROOT / "run_impacted_retry_rerun.sh")
    parser.add_argument("--benchmark", type=Path, default=ROOT / "data/benchmark/vulnbench_200.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--adapter-max-attempts", type=int, default=3)
    parser.add_argument("--backoff-base-s", type=float, default=2.0)
    parser.add_argument("--backoff-max-s", type=float, default=60.0)
    parser.add_argument("--backoff-jitter-s", type=float, default=0.5)
    parser.add_argument("--judge-models", nargs="+", required=True)
    parser.add_argument("--reasoning-exclude", action="store_true")
    parser.add_argument("--reasoning-max-tokens")
    parser.add_argument("--python", type=Path, default=ROOT / ".venv/bin/python")
    parser.add_argument("--poll-seconds", type=int, default=60)
    parser.add_argument("--max-total-active", type=int, default=4)
    parser.add_argument("--max-process-attempts", type=int, default=3)
    parser.add_argument("--pause-pid", type=int, action="append", default=[])
    parser.add_argument("--resume-pid", type=int, action="append", default=[])
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    args.benchmark = args.benchmark.resolve()
    args.runner = args.runner.resolve()
    args.output_dir = args.output_dir.resolve()
    args.log_dir = args.log_dir.resolve()
    # Keep the venv symlink path intact. Resolving it points at the underlying
    # system interpreter on macOS and bypasses the virtualenv site-packages.
    if not args.python.is_absolute():
        args.python = ROOT / args.python

    if args.pause_pid:
        stop_pids(args.pause_pid)

    env = os.environ.copy()
    env.update(load_dotenv(ROOT / ".env"))
    if "OPENROUTER_API_KEY" not in env:
        raise SystemExit("OPENROUTER_API_KEY is not set")

    models = parse_models(args.runner)
    attempts = {model: 0 for model in models}
    running: dict[str, subprocess.Popen[bytes]] = {}

    print(f"[START] supervisor models={len(models)} max_total_active={args.max_total_active}", flush=True)
    try:
        while True:
            external_active = active_models()

            for model, proc in list(running.items()):
                rc = proc.poll()
                if rc is None:
                    continue
                log = getattr(proc, "_vulnbench_log", None)
                if log is not None:
                    log.close()
                del running[model]
                output = args.output_dir / f"best{args.runs}_{safe_name(model)}.json"
                if is_complete(output, args.benchmark):
                    print(f"[DONE] {model} rc={rc} {aggregate_summary(output)}", flush=True)
                else:
                    print(f"[EXIT] {model} rc={rc} incomplete", flush=True)

            complete = []
            missing = []
            for model in models:
                output = args.output_dir / f"best{args.runs}_{safe_name(model)}.json"
                if is_complete(output, args.benchmark):
                    complete.append(model)
                else:
                    missing.append(model)

            if len(complete) == len(models):
                print("[COMPLETE] all intended reports are present and valid", flush=True)
                if args.resume_pid:
                    resume_pids(args.resume_pid)
                return 0

            active_now = active_models()
            total_active = len(active_now)
            launch_slots = max(0, args.max_total_active - total_active)
            for model in missing:
                if launch_slots <= 0:
                    break
                if model in active_now or model in running:
                    continue
                if attempts[model] >= args.max_process_attempts:
                    continue
                attempts[model] += 1
                print(f"[LAUNCH] {model} attempt={attempts[model]}", flush=True)
                running[model] = launch_model(model, args, env, attempts[model])
                launch_slots -= 1
                active_now = active_models()

            exhausted = [
                model
                for model in missing
                if attempts[model] >= args.max_process_attempts
                and model not in active_models()
                and model not in running
            ]
            if exhausted and len(exhausted) == len(missing):
                print("[FAILED] remaining models exhausted process attempts:", flush=True)
                for model in exhausted:
                    print(f"  {model}", flush=True)
                if args.resume_pid:
                    resume_pids(args.resume_pid)
                return 1

            print(
                f"[STATUS] complete={len(complete)}/{len(models)} "
                f"active={len(active_models())} supervised={len(running)} "
                f"missing={len(missing)}",
                flush=True,
            )
            time.sleep(args.poll_seconds)
    finally:
        for proc in running.values():
            log = getattr(proc, "_vulnbench_log", None)
            if log is not None:
                log.close()


if __name__ == "__main__":
    sys.exit(main())
