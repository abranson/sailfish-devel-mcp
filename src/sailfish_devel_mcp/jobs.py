"""CLI companions for detached MCP jobs; waits do not require model turns."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from .config import load_config
from . import tools


def run_operation(path: Path) -> int:
    request = json.loads(path.read_text(encoding="utf-8"))
    config_path = path.with_name("config.json")
    tools._write_json_atomic(config_path, request["config"])
    config = load_config(config_path)
    arguments = {**request["arguments"], "wait": True}
    if request["operation"] == "install":
        result = tools.handle_device_install_rpm(config, arguments)
    elif request["operation"] == "device_setup":
        result = tools.handle_device_setup(config, arguments)
    else:
        raise ValueError("unknown detached operation")
    tools._write_json_atomic(path.with_name("result.json"), result)
    for item in result.get("content", []):
        if item.get("type") == "text":
            print(item["text"], flush=True)
    return 1 if result.get("isError") else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("status", "wait", "log", "run-operation"))
    parser.add_argument("request", nargs="?", type=Path)
    parser.add_argument("--config")
    parser.add_argument("--kind", choices=("build", "device", "android"), default="build")
    parser.add_argument("--job-id")
    parser.add_argument("--host")
    parser.add_argument("--state-dir", help="Remote Android job directory override")
    parser.add_argument("--timeout", type=float, default=21600, help="Wait deadline, seconds; expiration does not cancel the job")
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--max-bytes", type=int, default=6000)
    args = parser.parse_args(argv)
    if args.action == "run-operation":
        if not args.request:
            parser.error("run-operation requires a private request file")
        return run_operation(args.request)
    if args.timeout <= 0 or args.interval <= 0:
        parser.error("timeout and interval must be positive")
    if args.action in {"wait", "log"} and not args.job_id:
        parser.error("wait/log requires --job-id")
    if args.action == "log" and args.kind == "android":
        parser.error("Android log pages are remote; use sailfish_android_build_status with lines")
    config = load_config(args.config)
    handler = {"build": tools.handle_build_status, "device": tools.handle_device_command_status,
               "android": tools.handle_android_build_status}[args.kind]
    arguments = {"job_id": args.job_id, "lines": 0}
    if args.host:
        arguments["host"] = args.host
    if args.state_dir:
        arguments["state_dir"] = args.state_dir
    if args.action == "log":
        arguments.update(log_offset=args.offset, max_bytes=args.max_bytes)
    deadline = time.monotonic() + args.timeout
    while True:
        if args.kind == "android":
            arguments["timeout"] = max(1, min(15, int(deadline - time.monotonic())))
        result = handler(config, arguments)
        data = result.get("structuredContent", {})
        terminal = tools._job_is_terminal(data)
        expired = time.monotonic() >= deadline
        if args.action != "wait" or terminal or result.get("isError") or expired:
            print(json.dumps(result, separators=(",", ":")))
            if expired and not terminal and args.action == "wait":
                return 124
            return 1 if result.get("isError") or data.get("state") == "cancelled" else 0
        time.sleep(min(args.interval, max(0, deadline - time.monotonic())))


if __name__ == "__main__":
    raise SystemExit(main())
