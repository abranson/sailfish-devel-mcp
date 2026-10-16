from __future__ import annotations

import base64
import functools
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import time
from typing import Any, Callable
from urllib.parse import quote
import uuid

from .config import AndroidBuildHostConfig, Config, DeviceConfig
from .runner import (
    CommandResult,
    remote_command,
    run,
    scp_from_argv,
    scp_to_argv,
    ssh_argv,
    truncate,
    user_bus_env,
)
from .vendor import build_sailfishos
from .qml import ternary_translation_findings
from .prerequisites import DEVICE_FEATURES, probe_report, probe_script, probe_tools, selected_features


def _source_identity(root: Path) -> dict[str, Any]:
    """Hash shipped source, including uncommitted changes, without invoking Git."""
    files = {}
    try:
        for path in sorted(root.rglob("*.py")):
            files[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        return {"sha256": None, "error": str(exc)}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return {"sha256": digest, "files": len(files)}


_SOURCE_ROOT = Path(__file__).resolve().parent
_HOST_LOADED_UTC = datetime.now(timezone.utc).isoformat()
_STARTUP_SOURCE = _source_identity(_SOURCE_ROOT)


def _process_started_utc() -> str | None:
    try:
        boot = next(int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines()
                    if line.startswith("btime "))
        # comm can contain spaces and parentheses; fields after it start at 3.
        fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        started = boot + int(fields[19]) / os.sysconf("SC_CLK_TCK")
        return datetime.fromtimestamp(started, timezone.utc).isoformat()
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _host_runtime_identity() -> dict[str, Any]:
    current = _source_identity(_SOURCE_ROOT)
    known = bool(_STARTUP_SOURCE.get("sha256") and current.get("sha256"))
    return {"pid": os.getpid(), "process_started_utc": _process_started_utc(),
            "loaded_utc": _HOST_LOADED_UTC,
            "source_root": str(_SOURCE_ROOT), "startup_source": _STARTUP_SOURCE,
            "disk_source": current,
            "restart_needed": current["sha256"] != _STARTUP_SOURCE["sha256"] if known else None}


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]
_BACKGROUND_SUPERVISORS: dict[int, subprocess.Popen[Any]] = {}
OBSERVED_MCP_TRANSPORT_LIFETIME_SECONDS = 20
MCP_TRANSPORT_SAFETY_MARGIN_SECONDS = 5
# Reaching the observed lifetime exactly leaves no time to serialize and
# deliver the response before the client closes the transport.
MAX_MCP_WAIT_SECONDS = (
    OBSERVED_MCP_TRANSPORT_LIFETIME_SECONDS - MCP_TRANSPORT_SAFETY_MARGIN_SECONDS
)


def _reap_background_supervisors() -> None:
    for pid, process in list(_BACKGROUND_SUPERVISORS.items()):
        if process.poll() is not None:
            _BACKGROUND_SUPERVISORS.pop(pid, None)


@dataclass(frozen=True)
class Tool:
    spec: dict[str, Any]
    handler: ToolHandler


def _status_response(handler):
    @functools.wraps(handler)
    def wrapped(config, args):
        result = handler(config, args)
        data = result.get("structuredContent", {})
        if not args.get("job_id") or "state" not in data:
            return result
        stable = {key: value for key, value in data.items() if key not in {
            "polls", "waited_seconds", "wait_expired", "transport", "log_tail",
            "log_chars", "log_kind", "log_included", "next_offset", "eof",
        }}
        revision = hashlib.sha256(json.dumps(stable, sort_keys=True).encode()).hexdigest()[:20]
        if (args.get("after_revision") == revision and not args.get("lines")
                and not args.get("verbose") and "log_offset" not in args):
            return {"content": [{"type": "text", "text": "unchanged"}],
                    "structuredContent": {"job_id": args["job_id"], "state": data["state"],
                                          "revision": revision, "unchanged": True},
                    "isError": result.get("isError", False)}
        data["revision"] = revision
        return result
    return wrapped


def build_registry(config: Config) -> dict[str, Tool]:
    tools = [
        Tool({"name": "sailfish_doctor", "description": "Check helper compatibility, local tools, SDK targets and configuration without contacting devices.",
              "inputSchema": _object_schema({}), "annotations": _read_only_annotations("Sailfish environment")},
             lambda args: handle_doctor(config, args)),
        Tool(_spec_obs_watch(), lambda args: handle_obs_watch(config, args)),
        Tool(_spec_devices(), lambda args: handle_devices(config, args)),
        Tool(_spec_device_setup(), lambda args: handle_device_setup(config, args)),
        Tool(_spec_device_journal(), lambda args: handle_device_journal(config, args)),
        Tool(_spec_device_topmost_pid(), lambda args: handle_device_topmost_pid(config, args)),
        Tool(_spec_device_proc_maps(), lambda args: handle_device_proc_maps(config, args)),
        Tool(
            _spec_device_lipstick_screenshot(),
            lambda args: handle_device_lipstick_screenshot(config, args),
        ),
        Tool(
            _spec_device_touch(),
            lambda args: handle_device_touch(config, args),
        ),
        Tool(
            _spec_device_touch_workflow(),
            lambda args: handle_device_touch_workflow(config, args),
        ),
        Tool(
            _spec_device_user_bus_call(),
            lambda args: handle_device_user_bus_call(config, args),
        ),
        Tool(
            _spec_device_user_session_command(),
            lambda args: handle_device_user_session_command(config, args),
        ),
        Tool(
            _spec_device_command_start(),
            lambda args: handle_device_command_start(config, args),
        ),
        Tool(
            _spec_device_command_status(),
            lambda args: handle_device_command_status(config, args),
        ),
        Tool(
            _spec_device_command_cancel(),
            lambda args: handle_device_command_cancel(config, args),
        ),
        Tool(_spec_device_install_rpm(), lambda args: handle_device_install_rpm(config, args)),
        Tool(
            _spec_device_restart_service(),
            lambda args: handle_device_restart_service(config, args),
        ),
        Tool(
            _spec_device_app_launch(),
            lambda args: handle_device_app_launch(config, args),
        ),
        Tool(
            _spec_device_browser_launch(),
            lambda args: handle_device_browser_launch(config, args),
        ),
        Tool(_spec_build_rpm(), lambda args: handle_build_rpm(config, args)),
        Tool(_spec_build_preflight(), lambda args: handle_build_preflight(config, args)),
        Tool(_spec_build_status(), lambda args: handle_build_status(config, args)),
        Tool(_spec_build_cancel(), lambda args: handle_build_cancel(config, args)),
        Tool(
            _spec_android_build_hosts(),
            lambda args: handle_android_build_hosts(config, args),
        ),
        Tool(
            _spec_android_build(),
            lambda args: handle_android_build(config, args),
        ),
        Tool(
            _spec_android_build_status(),
            lambda args: handle_android_build_status(config, args),
        ),
        Tool(
            _spec_android_build_cancel(),
            lambda args: handle_android_build_cancel(config, args),
        ),
        Tool(
            _spec_sdk_refresh_metadata(),
            lambda args: handle_sdk_refresh_metadata(config, args),
        ),
        Tool(_spec_obs_results(), lambda args: handle_obs_results(config, args)),
        Tool(_spec_obs_buildlog(), lambda args: handle_obs_buildlog(config, args)),
        Tool(_spec_repo_status(), lambda args: handle_repo_status(config, args)),
        Tool(_spec_repo_find(), lambda args: handle_repo_find(config, args)),
        Tool(_spec_spec_summary(), lambda args: handle_spec_summary(config, args)),
        Tool(
            _spec_qml_find_translations(),
            lambda args: handle_qml_find_translations(config, args),
        ),
        Tool(
            _spec_qml_check_translator_ternaries(),
            lambda args: handle_qml_check_translator_ternaries(config, args),
        ),
    ]
    from .companion_host import register as companion_tools
    tools.extend(companion_tools(config))
    return {tool.spec["name"]: tool for tool in tools}


def handle_devices(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    structured = config.public_dict()
    text = "\n".join(
        (
            f"{name}: {device.ssh_target}"
            f" user={device.username}"
            f"{f' arch={device.architecture}' if device.architecture else ''}"
            f"{f' release={device.release}' if device.release else ''}"
        )
        for name, device in sorted(config.devices.items(), key=lambda item: item[0])
    )
    return ok_text(text or "No configured devices", structured)


def _device_prerequisite_report(
    config: Config, device: DeviceConfig, features: list[str],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    result = _run_ssh(
        config, device,
        ["sh", "-c", probe_script(), "device-prerequisites", device.username,
         device.user_bus_address, *probe_tools(features)],
        timeout=MAX_MCP_WAIT_SECONDS,
    )
    if not result.ok:
        return None, command_result("device prerequisites", result)
    report = probe_report(features, result.stdout)
    report["device"] = device.name
    return report, None


def handle_device_setup(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    from .companion_host import invoke
    mode = args.get("companion", "none")
    if mode not in ("none", "check", "deploy"):
        raise ValueError("companion must be none, check or deploy")
    approved = _bool_arg(args, "confirm_companion_install", default=False)
    if approved and mode != "deploy":
        raise ValueError("confirm_companion_install requires companion=deploy")
    if mode != "none":
        args = dict(args, features=list(dict.fromkeys(selected_features(args) + ["companion"])))
    result = _handle_device_prerequisites(config, args)
    report = result.get("structuredContent", {})
    # Detached prerequisite workers re-enter this handler with wait=true.
    if mode == "none" or result.get("isError") or "ready" not in report:
        return result
    if not report["ready"]:
        return result
    companion_result = invoke(config, "manage", {
        **({"device": args["device"]} if "device" in args else {}),
        "action": "deploy" if mode == "deploy" else "status",
        "confirm_initial_install": approved,
    }, allow_deploy=True)
    report["companion"] = companion_result.get("structuredContent", {})
    if companion_result.get("isError"):
        report["companion_error"] = companion_result.get("content", [])
        return tool_error("device prerequisites checked; companion operation failed", report)
    return ok_text(json.dumps(report, indent=2, sort_keys=True), report)


def _handle_device_prerequisites(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    features = selected_features(args)
    install_missing = _bool_arg(args, "install_missing", default=False)
    wait = _bool_arg(args, "wait", default=False)
    timeout = _int_arg(args, "timeout", default=600, minimum=1, maximum=1200)
    report, error = _device_prerequisite_report(config, device, features)
    if error:
        return error
    if not install_missing or not report["installable_packages"]:
        result = ok_text(json.dumps(report, indent=2, sort_keys=True), report)
        result["isError"] = install_missing and not report["ready"]
        return result
    if report["uid"] != 0:
        return tool_error("install_missing requires a root SSH login; no privilege escalation is attempted", report)
    if not (report["tools"]["pkcon"] or report["tools"]["zypper"]):
        return tool_error("pkcon or zypper is required to install optional device packages", report)
    if not wait:
        return _start_operation(config, args, "device_setup", "install device prerequisites", timeout)
    packages = report["installable_packages"]
    if report["tools"]["pkcon"]:
        command = ["pkcon", "install", "-y", *packages]
    else:
        command = ["zypper", "--non-interactive", "install", "--no-recommends", *packages]
    installed = _run_ssh(config, device, command, timeout=timeout)
    if not installed.ok:
        return command_result("install device prerequisites", installed, report)
    report, error = _device_prerequisite_report(config, device, features)
    if error:
        return error
    report["requested_packages"] = packages
    result = ok_text(json.dumps(report, indent=2, sort_keys=True), report)
    result["isError"] = not report["ready"]
    return result


def handle_device_journal(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    lines = _int_arg(args, "lines", default=200, minimum=1, maximum=5000)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=600)

    command = ["journalctl", "--no-pager", "-n", str(lines)]
    unit = _optional_str(args, "unit")
    since = _optional_str(args, "since")
    grep = _optional_str(args, "grep")
    if unit:
        command += ["-u", unit]
    if since:
        command += ["--since", since]
    result = _run_device(config, device, command, timeout=timeout, extra={"filter": {"contains": grep}})
    stdout = result.stdout
    if grep:
        stdout = "\n".join(line for line in stdout.splitlines() if grep in line)
        result = CommandResult(result.argv, result.returncode, stdout, result.stderr, result.metadata)
    return command_result("device journal", result)


def handle_device_topmost_pid(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    timeout = _int_arg(args, "timeout", default=20, minimum=1, maximum=120)
    command = user_bus_env(device) + [
        "dbus-send",
        "--session",
        "--print-reply",
        "--dest=org.nemomobile.lipstick",
        "/",
        "org.nemomobile.compositor.privateTopmostWindowProcessId",
    ]
    result = _run_device(config, device, command, timeout=timeout, user=True)
    pid = _parse_dbus_integer(result.stdout)
    structured = result.summary_dict()
    structured["pid"] = pid
    text = f"topmost PID: {pid}" if pid is not None else _command_text("topmost PID", result)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured,
        "isError": not result.ok or pid is None,
    }


def handle_device_proc_maps(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    pid = _int_arg(args, "pid", minimum=1)
    contains = _optional_str(args, "contains")
    max_lines = _int_arg(args, "max_lines", default=200, minimum=1, maximum=5000)
    timeout = _int_arg(args, "timeout", default=20, minimum=1, maximum=120)

    result = _run_device(config, device, ["cat", f"/proc/{pid}/maps"], timeout=timeout,
                         extra={"filter": {"contains": contains, "max_lines": max_lines}})
    if result.metadata.get("backend") == "companion":
        return command_result("process maps", result, {"matched_lines": result.metadata["matched_lines"], "pid": pid})
    lines = result.stdout.splitlines()
    if contains:
        lines = [line for line in lines if contains in line]
    limited = lines[:max_lines]
    stdout = "\n".join(limited)
    if len(lines) > max_lines:
        stdout += f"\n[truncated after {max_lines} lines]"
    filtered = CommandResult(result.argv, result.returncode, stdout, result.stderr, result.metadata)
    return command_result("process maps", filtered, {"matched_lines": result.metadata.get("matched_lines", len(lines)), "pid": pid})


def _screenshot_plan(device, remote_path, privileged, timeout, name="screenshot"):
    return [
        {"name": name + "_prepare", "argv": ["sh", "-c", _screenshot_prepare_command(device, remote_path)], "timeout": timeout},
        {"name": name, "argv": ["dbus-send", "--session", "--print-reply",
            "--dest=org.nemomobile.lipstick", "/org/nemomobile/lipstick/screenshot",
            "org.nemomobile.lipstick.saveScreenshot", "string:" + remote_path],
         "user": True, "group": "privileged" if privileged else None, "timeout": timeout},
    ]


def _companion_touch_workflow(config, device, args, timeout):
    from .companion_host import optional_call
    privileged = _bool_arg(args, "privileged", default=True)
    plans = []
    screenshots = {}
    for phase in ("before", "after"):
        if not _bool_arg(args, "screenshot_" + phase, default=phase == "before"):
            continue
        remote = _optional_str(args, phase + "_remote_path") or _default_screenshot_path(device, "touch-" + phase)
        local = _optional_str(args, phase + "_local_path")
        if phase == "before":
            local = local or _optional_str(args, "local_path")
        local_path = _safe_output_path(config, local) if local else None
        screenshots[phase] = (remote, local_path)
    if "before" in screenshots:
        plans.extend(_screenshot_plan(device, screenshots["before"][0], privileged, timeout, "screenshot_before"))
    if _bool_arg(args, "discover_input", default=True) and not _optional_str(args, "input_device"):
        plan, _ = _touch_plan({"action": "discover", "timeout": timeout,
                              "include_evdev_trace": _bool_arg(args, "include_evdev_trace", default=False)})
        plans.append(plan)
    touch_plan, touch_data = _touch_plan(dict(args, timeout=timeout))
    plans.append(touch_plan)
    if "after" in screenshots:
        plans.extend(_screenshot_plan(device, screenshots["after"][0], privileged, timeout, "screenshot_after"))
    data = optional_call(config, device, "workflow", {"steps": plans, "timeout": timeout * len(plans)})
    if data is None:
        return None
    results = []
    for record in data["steps"]:
        name = record["name"]
        if name.endswith("_prepare") and record["returncode"] == 0:
            continue
        result = CommandResult(("device-companion", name), record["returncode"], record["stdout"], record["stderr"], {"backend": "companion"})
        extra = dict(touch_data) if name == "touch" else {}
        if name in ("screenshot_before", "screenshot_after"):
            phase = name.removeprefix("screenshot_")
            remote, local = screenshots[phase]
            extra["remote_path"] = remote
            if result.ok and local:
                local.parent.mkdir(parents=True, exist_ok=True)
                pull = run(scp_from_argv(device, config.paths.ssh_config, remote, local), timeout=timeout)
                extra.update(local_path=str(local), pull=pull.summary_dict())
                if not pull.ok:
                    # Device side effects already happened. Never rerun the workflow.
                    results.append((name, command_result("pull screenshot (device workflow already executed)", pull, extra)))
                    return combined_result("touch workflow", results)
        results.append((name, command_result(name, result, extra)))
    return combined_result("touch workflow", results)


def handle_device_lipstick_screenshot(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    home_path = _device_home_path(device)
    remote_path = _optional_str(args, "remote_path") or (
        f"{home_path}/Pictures/Screenshots/lipstick-{timestamp}.png"
    )
    local_path_arg = _optional_str(args, "local_path")
    privileged = _bool_arg(args, "privileged", default=True)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=120)

    inner = remote_command(
        user_bus_env(device)
        + [
            "dbus-send",
            "--session",
            "--print-reply",
            "--dest=org.nemomobile.lipstick",
            "/org/nemomobile/lipstick/screenshot",
            "org.nemomobile.lipstick.saveScreenshot",
            f"string:{remote_path}",
        ]
    )
    prepare_dir = _screenshot_prepare_command(device, remote_path)
    dbus_call = f"sg privileged -c {shlex.quote(inner)}" if privileged else inner
    remote = f"{prepare_dir} && {dbus_call}"
    from .companion_host import routed
    plan = _screenshot_plan(device, remote_path, privileged, timeout)
    result = routed(config, device, ["sh", "-c", remote], timeout=timeout,
                    fallback=remote, steps=plan)

    structured: dict[str, Any] = result.summary_dict()
    structured["remote_path"] = remote_path
    if result.ok and local_path_arg:
        local_path = _safe_output_path(config, local_path_arg)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        pull = run(
            scp_from_argv(device, config.paths.ssh_config, remote_path, local_path),
            timeout=timeout,
        )
        structured["pull"] = pull.summary_dict()
        structured["local_path"] = str(local_path)
        if not pull.ok:
            return command_result("pull screenshot", pull, structured)
    return command_result("lipstick screenshot", result, structured)


def _touch_plan(args):
    action = _enum_arg(args, "action", ["discover", "tap", "swipe"])
    timeout = _int_arg(args, "timeout", default=10, minimum=1, maximum=120)
    input_device = _optional_str(args, "input_device")
    if input_device and not re.fullmatch(r"/dev/input/event\d+", input_device):
        raise ValueError("input_device must look like /dev/input/event<N>")

    if action == "discover":
        include_evdev_trace = _bool_arg(args, "include_evdev_trace", default=False)
        remote = _touch_discover_command(include_evdev_trace)
        return {"name": "touchscreen_discovery", "argv": ["sh", "-c", remote], "timeout": timeout}, {}


    values: dict[str, str | int] = {"ACTION": action}
    if input_device:
        values["INPUT_DEVICE"] = input_device

    if action == "tap":
        values["X"] = _int_arg(args, "x", minimum=0, maximum=10000)
        values["Y"] = _int_arg(args, "y", minimum=0, maximum=10000)
        values["HOLD_MS"] = _int_arg(args, "hold_ms", default=80, minimum=1, maximum=5000)
    else:
        values["START_X"] = _int_arg(args, "start_x", minimum=0, maximum=10000)
        values["START_Y"] = _int_arg(args, "start_y", minimum=0, maximum=10000)
        values["END_X"] = _int_arg(args, "end_x", minimum=0, maximum=10000)
        values["END_Y"] = _int_arg(args, "end_y", minimum=0, maximum=10000)
        values["DURATION_MS"] = _int_arg(args, "duration_ms", default=300, minimum=1, maximum=10000)
        values["STEPS"] = _int_arg(args, "steps", default=12, minimum=1, maximum=200)

    remote = _touch_inject_command(values)
    structured = {
        "action": action,
        "input_device": input_device,
    }
    return {"name": "touch", "argv": ["sh", "-c", remote], "timeout": timeout}, structured


def handle_device_touch(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    try:
        plan, structured = _touch_plan(args)
    except ValueError as exc:
        if str(exc).startswith("input_device must"):
            return tool_error(str(exc))
        raise
    result = _run_device(config, device, plan["argv"], timeout=plan["timeout"])
    return command_result("touchscreen discovery" if plan["name"] == "touchscreen_discovery" else "device touch", result, structured)


def handle_device_touch_workflow(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    action = _enum_arg(args, "action", ["tap", "swipe"])
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=300)
    screenshot_before = _bool_arg(args, "screenshot_before", default=True)
    screenshot_after = _bool_arg(args, "screenshot_after", default=False)
    discover_input = _bool_arg(args, "discover_input", default=True)
    privileged = _bool_arg(args, "privileged", default=True)

    companion_result = _companion_touch_workflow(config, device, args, timeout)
    if companion_result is not None:
        return companion_result

    steps: list[tuple[str, dict[str, Any]]] = []
    base_args = {"device": _optional_str(args, "device") or device.name, "timeout": timeout}

    def append_step(name: str, result: dict[str, Any]) -> bool:
        steps.append((name, result))
        return bool(result.get("isError", False))

    if screenshot_before:
        before_args: dict[str, Any] = {
            **base_args,
            "privileged": privileged,
            "remote_path": _optional_str(args, "before_remote_path")
            or _default_screenshot_path(device, "touch-before"),
        }
        before_local_path = _optional_str(args, "before_local_path") or _optional_str(args, "local_path")
        if before_local_path:
            before_args["local_path"] = before_local_path
        if append_step("screenshot_before", handle_device_lipstick_screenshot(config, before_args)):
            return combined_result("touch workflow", steps)

    input_device = _optional_str(args, "input_device")
    if discover_input and not input_device:
        discover_args = {
            **base_args,
            "action": "discover",
            "include_evdev_trace": _bool_arg(args, "include_evdev_trace", default=False),
        }
        if append_step("touchscreen_discovery", handle_device_touch(config, discover_args)):
            return combined_result("touch workflow", steps)

    touch_args = dict(args)
    touch_args["action"] = action
    touch_args["timeout"] = timeout
    if append_step("touch", handle_device_touch(config, touch_args)):
        return combined_result("touch workflow", steps)

    if screenshot_after:
        after_args: dict[str, Any] = {
            **base_args,
            "privileged": privileged,
            "remote_path": _optional_str(args, "after_remote_path")
            or _default_screenshot_path(device, "touch-after"),
        }
        after_local_path = _optional_str(args, "after_local_path")
        if after_local_path:
            after_args["local_path"] = after_local_path
        append_step("screenshot_after", handle_device_lipstick_screenshot(config, after_args))

    return combined_result("touch workflow", steps)


def handle_device_user_bus_call(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    destination = _str_arg(args, "destination")
    path = _str_arg(args, "path")
    interface = _str_arg(args, "interface")
    member = _str_arg(args, "member")
    dbus_args = args.get("arguments") or []
    if not isinstance(dbus_args, list) or not all(isinstance(item, str) for item in dbus_args):
        return tool_error("arguments must be a list of dbus-send argument strings")
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=300)
    command = user_bus_env(device) + [
        "dbus-send",
        "--session",
        "--print-reply",
        f"--dest={destination}",
        path,
        f"{interface}.{member}",
        *dbus_args,
    ]
    return command_result("user bus call", _run_device(config, device, command, timeout=timeout, user=True))


def handle_device_user_session_command(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    command = _command_list_arg(args, "command")
    timeout = _int_arg(
        args,
        "timeout",
        default=MAX_MCP_WAIT_SECONDS,
        minimum=1,
        maximum=MAX_MCP_WAIT_SECONDS,
    )
    run_as_user = _bool_arg(args, "run_as_user", default=False)
    from .companion_host import routed
    result = routed(config, device, user_bus_env(device) + command, timeout=timeout,
                    user=run_as_user,
                    fallback=_device_user_session_argv(config, device, command, run_as_user=run_as_user)[-1])
    return command_result(
        "user session command",
        result,
        {"run_as_user": run_as_user, "username": device.username},
        verbose=_bool_arg(args, "verbose", default=False),
    )


def handle_device_command_start(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    command = _command_list_arg(args, "command")
    timeout = _int_arg(args, "timeout", default=3600, minimum=1, maximum=86400)
    run_as_user = _bool_arg(args, "run_as_user", default=False)
    from .companion_host import start_job
    companion_result = start_job(config, device, dict(args, command=command, timeout=timeout, run_as_user=run_as_user))
    if companion_result is not None:
        return companion_result
    argv = _device_user_session_argv(
        config,
        device,
        command,
        run_as_user=run_as_user,
    )
    job = _start_background_command(
        f"device command on {device.name}",
        argv,
        timeout=timeout,
        jobs_dir=_device_command_jobs_dir(),
        job_prefix="device",
        log_name="command.log",
        status_fields={
            "job_kind": "device_command",
            "device": device.name,
            "username": device.username,
            "run_as_user": run_as_user,
        },
    )
    text = "\n".join(
        [
            f"started device command job {job['job_id']} on {device.name}",
            f"status: {job['status_path']}",
            f"log: {job['log_path']}",
            (
                "wait with sailfish_device_command_status "
                f"wait_seconds={MAX_MCP_WAIT_SECONDS} and lines=0"
            ),
        ]
    )
    return ok_text(text, _compact_device_command_status(job))


@_status_response
def handle_device_command_status(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    job_id = _optional_str(args, "job_id")
    lines = _int_arg(args, "lines", default=0, minimum=0, maximum=1000)
    wait_seconds = _int_arg(
        args,
        "wait_seconds",
        default=0,
        minimum=0,
        maximum=MAX_MCP_WAIT_SECONDS,
    )
    verbose = _bool_arg(args, "verbose", default=False)
    jobs_dir = _device_command_jobs_dir()
    if not job_id:
        jobs = []
        if jobs_dir.exists():
            for status_path in sorted(
                jobs_dir.glob("*/status.json"),
                key=lambda path: path.stat().st_mtime,
            ):
                if not _valid_local_job_id(status_path.parent.name):
                    continue
                status = _read_job_status(status_path)
                if status:
                    status = _with_supervisor_health(status, status_path.parent)
                    jobs.append(status if verbose else _compact_device_command_status(status))
        jobs = jobs[-20:]
        text = "\n".join(
            f"{job.get('job_id')}: {job.get('state')} {job.get('started_at', '')}"
            for job in jobs
        )
        return ok_text(
            text or "no device command jobs found",
            {"jobs_dir": str(jobs_dir), "jobs": jobs},
        )

    from .companion_host import job_operation
    companion_result = job_operation(config, args)
    if companion_result is not None:
        return companion_result
    _validate_local_job_id(job_id)
    job_dir = _local_job_dir(jobs_dir, job_id)
    status_path = job_dir / "status.json"
    if not status_path.exists():
        return tool_error(
            f"unknown device command job: {job_id}",
            {"jobs_dir": str(jobs_dir)},
        )
    deadline = time.monotonic() + wait_seconds
    status = _read_job_status(status_path)
    if status:
        status = _with_supervisor_health(status, job_dir)
    while status and wait_seconds and not _job_is_terminal(status):
        if time.monotonic() >= deadline:
            break
        time.sleep(0.25)
        status = _read_job_status(status_path)
        if status:
            status = _with_supervisor_health(status, job_dir)
    if not status:
        return tool_error(f"could not read device command job status: {job_id}")

    state = str(status.get("state") or "unknown")
    returncode = status.get("returncode")
    log_path = job_dir / "command.log"
    page = {}
    if "log_offset" in args:
        log_tail, page = _log_page(log_path, _int_arg(args, "log_offset", minimum=0, default=0),
                                  _int_arg(args, "max_bytes", default=6000, minimum=1, maximum=12000))
        log_kind = "page"
    elif lines:
        log_tail = _tail_file(log_path, lines)
        log_kind = "tail"
    elif state in {"failed", "timed_out"} or (
        state == "finished" and returncode not in (0, None)
    ):
        log_tail = _failure_excerpt_from_file(log_path)
        log_kind = "failure_excerpt"
    else:
        log_tail = ""
        log_kind = "none"
    text_lines = [
        f"job_id: {status.get('job_id')}",
        f"state: {state}",
        f"returncode: {returncode}",
        f"device: {status.get('device', '')}",
        f"log: {log_path}",
    ]
    if status.get("failure_class"):
        text_lines.append(
            f"failure: {status.get('failure_class')}: {status.get('failure_message', '')}"
        )
    if log_tail:
        text_lines += ["", log_tail]
    structured = dict(status) if verbose else _compact_device_command_status(status)
    structured.update(page)
    structured.update(
        log_included=bool(log_tail),
        log_kind=log_kind,
        log_chars=len(log_tail),
    )
    if verbose:
        structured["log_tail"] = log_tail
    return {
        "content": [{"type": "text", "text": "\n".join(text_lines)}],
        "structuredContent": structured,
        "isError": state in {"failed", "timed_out"} or (
            state == "finished" and returncode not in (0, None)
        ),
    }


def handle_device_command_cancel(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    job_id = _str_arg(args, "job_id")
    _validate_local_job_id(job_id)
    from .companion_host import job_operation
    companion_result = job_operation(config, args, cancel=True)
    if companion_result is not None:
        return companion_result
    job_dir = _local_job_dir(_device_command_jobs_dir(), job_id)
    status = _read_job_status(job_dir / "status.json")
    if status is None:
        return tool_error(f"unknown device command job: {job_id}")
    if _job_is_terminal(status):
        return ok_text(
            f"device command job {job_id} is already {status.get('state')}",
            _compact_device_command_status(status),
        )
    (job_dir / "cancel.requested").write_text(
        datetime.now(timezone.utc).isoformat() + "\n",
        encoding="utf-8",
    )
    structured = _compact_device_command_status(status)
    structured["cancel_requested"] = True
    return ok_text(f"cancellation requested for device command job {job_id}", structured)


def handle_device_install_rpm(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    # Validate paths and option shapes before allocating the detached transaction.
    device = _device(config, args)
    rpm_path_arg = _optional_str(args, "rpm_path")
    rpm_paths_arg = args.get("rpm_paths")
    if rpm_path_arg and rpm_paths_arg is not None:
        return tool_error("use either rpm_path or rpm_paths, not both")
    if rpm_paths_arg is not None:
        rpm_path_values = _string_list_arg(args, "rpm_paths")
        if not rpm_path_values:
            return tool_error("rpm_paths must contain at least one RPM")
    elif rpm_path_arg:
        rpm_path_values = [rpm_path_arg]
    else:
        return tool_error("rpm_path or rpm_paths is required")

    rpm_paths = [
        _safe_input_path(config, value, allow_tmp=True)
        for value in rpm_path_values
    ]
    remote_path = _optional_str(args, "remote_path")
    remote_dir = _optional_str(args, "remote_dir")
    if len(rpm_paths) > 1 and remote_path:
        return tool_error("remote_path only supports a single RPM; use remote_dir with rpm_paths")
    if len(rpm_paths) > 1 and len({path.name for path in rpm_paths}) != len(rpm_paths):
        return tool_error("rpm_paths must not contain duplicate file names")

    installer = _enum_arg(args, "installer", ["pkcon", "rpm"], default="pkcon")
    timeout = _int_arg(args, "timeout", default=180, minimum=1, maximum=1200)

    if not _bool_arg(args, "wait", default=False):
        for path in rpm_paths:
            if not path.is_file() or path.suffix != ".rpm":
                raise ValueError(f"RPM file not found: {path}")
        if remote_dir:
            _remote_absolute_path(remote_dir, "remote_dir")
        return _start_operation(config, args, "install", "install RPM", timeout)

    mkdir_result: CommandResult | None = None
    if len(rpm_paths) == 1 and not remote_dir:
        remote_paths = [remote_path or f"/tmp/{rpm_paths[0].name}"]
    else:
        remote_dir = _remote_absolute_path(remote_dir or _new_remote_rpm_dir(), "remote_dir")
        mkdir_result = _run_ssh(config, device, ["mkdir", "-p", remote_dir], timeout=timeout)
        if not mkdir_result.ok:
            return command_result("prepare RPM directory", mkdir_result, {"remote_dir": remote_dir})
        remote_paths = [
            str(PurePosixPath(remote_dir) / rpm_path.name)
            for rpm_path in rpm_paths
        ]

    copy_results = []
    for rpm_path, target_path in zip(rpm_paths, remote_paths):
        copy_result = run(
            scp_to_argv(device, config.paths.ssh_config, rpm_path, target_path),
            timeout=timeout,
        )
        copy_results.append(copy_result)
        if not copy_result.ok:
            return command_result(
                "copy RPM to device",
                copy_result,
                {
                    "copies": [result.summary_dict() for result in copy_results],
                    "remote_paths": remote_paths,
                },
            )

    if installer == "pkcon":
        remote = ["pkcon", "install-local", "-y", *remote_paths]
    else:
        remote = ["rpm", "-Uvh", "--replacepkgs", *remote_paths]
    install_result = _run_ssh(config, device, remote, timeout=timeout)
    structured = {
        "copy": copy_results[0].summary_dict(),
        "copies": [result.summary_dict() for result in copy_results],
        "install": install_result.summary_dict(),
        "remote_path": remote_paths[0],
        "remote_paths": remote_paths,
        "remote_dir": remote_dir,
        "installer": installer,
    }
    if mkdir_result is not None:
        structured["mkdir"] = mkdir_result.summary_dict()
    return command_result("install RPM", install_result, structured)


def handle_device_restart_service(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    unit = _service_unit_arg(args, "unit")
    action = _enum_arg(args, "action", ["restart", "start", "stop", "status"], default="restart")
    mode = _enum_arg(args, "mode", ["system", "user"], default="system")
    timeout = _int_arg(args, "timeout", default=60, minimum=1, maximum=300)
    if mode == "user":
        command = user_bus_env(device) + ["systemctl", "--user", action, unit]
    else:
        command = ["systemctl", action, unit]
    if unit == "sailfish-devel-companion.service" and mode == "system":
        return command_result(f"{mode} service {action}", _run_ssh(config, device, command, timeout=timeout))
    return command_result(
        f"{mode} service {action}",
        _run_device(config, device, command, timeout=timeout, user=mode == "user",
                    extra={"service": {"unit": unit, "mode": mode}}),
    )


def handle_device_app_launch(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    desktop_file = _str_arg(args, "desktop_file")
    path = PurePosixPath(desktop_file)
    if ("\x00" in desktop_file or "\n" in desktop_file
            or ".." in path.parts or not desktop_file.endswith(".desktop")):
        raise ValueError("desktop_file must be a .desktop basename or absolute path")
    if not path.is_absolute():
        if len(path.parts) != 1 or desktop_file.startswith("-"):
            raise ValueError("desktop_file must be a .desktop basename or absolute path")
        desktop_file = "/usr/share/applications/" + desktop_file
    wait_seconds = _int_arg(args, "wait_seconds", default=1, minimum=0, maximum=5)
    timeout = _int_arg(args, "timeout", default=15, minimum=1, maximum=15)
    if timeout <= wait_seconds:
        raise ValueError("timeout must exceed wait_seconds")
    from .companion_host import routed
    launch_command = ["sh", "-c", _app_launch_script(), "app-launch", device.username, desktop_file, str(wait_seconds)]
    result = routed(config, device, launch_command[:-1] + ["0"], timeout=timeout, user=True,
                    extra={"foreground": desktop_file, "foreground_wait": wait_seconds},
                    fallback=_device_user_session_argv(config, device, launch_command, run_as_user=True)[-1])
    receipt = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    launch_pid = receipt.get("launch_pid", "")
    exit_code = receipt.get("launch_exit_code", "")
    submitted = result.ok and launch_pid.isdigit()
    data = command_result(
        "app launch submitted (verify foreground and rendering)" if submitted else "app launch",
        result,
        {
            "desktop_file": desktop_file,
            "username": device.username,
            "submitted": submitted,
            "launch_pid": int(launch_pid) if launch_pid.isdigit() else None,
            "launch_exit_code": int(exit_code) if exit_code.isdigit() else None,
            "remote_log": receipt.get("remote_log"),
            "remote_status": receipt.get("remote_status"),
        },
    )
    data["isError"] = not submitted
    return data


def _app_launch_script() -> str:
    # Positional arguments keep desktop paths and usernames out of shell source.
    # Both the supervisor and gio descendants must release the SSH streams.
    return r'''set -eu
session_home=$(getent passwd "$1" | cut -d: -f6)
test -n "$session_home" && test -d "$session_home"
cd "$session_home"
export HOME="$session_home"
command -v gio >/dev/null
command -v nohup >/dev/null
test -r "$2"
umask 077
mkdir -p "$session_home/.cache/sailfish-devel-mcp"
launch_dir=$(mktemp -d "$session_home/.cache/sailfish-devel-mcp/launch.XXXXXX")
nohup sh -c '
    gio launch "$1"
    result=$?
    printf "%s\n" "$result" > "$2/exit-code.tmp"
    mv "$2/exit-code.tmp" "$2/exit-code"
    exit "$result"
' app-launch-worker "$2" "$launch_dir" </dev/null >"$launch_dir/launch.log" 2>&1 &
printf 'launch_pid=%s\nremote_log=%s\nremote_status=%s\n' "$!" "$launch_dir/launch.log" "$launch_dir/exit-code"
sleep "$3"
if [ -f "$launch_dir/exit-code" ]; then
    result=$(cat "$launch_dir/exit-code")
    printf 'launch_exit_code=%s\n' "$result"
    if [ "$result" -ne 0 ]; then
        tail -c 2000 "$launch_dir/launch.log" >&2
        exit "$result"
    fi
fi
'''


def handle_device_browser_launch(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    device = _device(config, args)
    url = _str_arg(args, "url")
    stop_stale = _bool_arg(args, "stop_stale", default=True)
    wait_seconds = _int_arg(args, "wait_seconds", default=3, minimum=0, maximum=60)
    timeout = _int_arg(args, "timeout", default=60, minimum=1, maximum=300)
    remote = _browser_launch_command(device, url, stop_stale, wait_seconds)
    result = _run_device(config, device, ["sh", "-c", remote], timeout=timeout)

    return command_result(
        "browser launch",
        result,
        {"url": url, "stop_stale": stop_stale, "wait_seconds": wait_seconds},
    )


def _sailfish_build_command(
    config: Config,
    args: dict[str, Any],
    *,
    dry_run: bool = False,
) -> tuple[list[str], Path]:
    project_path = _safe_input_path(config, _str_arg(args, "project_path"), allow_tmp=False)
    device = config.device(_optional_str(args, "device")) if args.get("device") else None
    script = config.paths.build_sailfishos
    if not script.exists():
        raise ValueError(f"build helper not found: {script}")

    command = ["python3", str(script), "--project-dir", str(project_path)]
    spec_path = _optional_str(args, "spec_path")
    if spec_path:
        command += ["--spec", spec_path]
    backend = _enum_arg(args, "backend", ["auto", "docker", "local"], default="auto")
    command += ["--backend", backend]
    release = _optional_str(args, "release") or (device.release if device else None)
    arches = args.get("arch")
    artifacts_dir = _optional_str(args, "artifacts_dir")
    local_sdk_arg = _optional_str(args, "local_sdk")
    if local_sdk_arg and backend == "docker":
        raise ValueError("local_sdk cannot be combined with the Docker backend")
    local_sdk = (
        _safe_local_sdk_path(config, local_sdk_arg)
        if local_sdk_arg
        else config.paths.local_sdk
    )
    snapshot_key = _optional_str(args, "snapshot_key")
    snapshot_repositories = _string_list_arg(args, "snapshot_repository")
    snapshot_packages = _string_list_arg(args, "snapshot_package")
    reset_snapshot = _bool_arg(args, "reset_snapshot", default=False)
    resume_snapshot = _bool_arg(args, "resume_snapshot", default=False)
    if reset_snapshot and resume_snapshot:
        raise ValueError("reset_snapshot and resume_snapshot are mutually exclusive")
    if (snapshot_key or snapshot_repositories or snapshot_packages or reset_snapshot or resume_snapshot) and backend == "docker":
        raise ValueError("snapshot options require the local backend")
    if backend != "docker":
        if local_sdk:
            command += ["--local-sdk", str(local_sdk)]
        if local_sdk and not release:
            release = "live"
        if snapshot_key:
            command += ["--snapshot-key", snapshot_key]
        if reset_snapshot:
            command.append("--reset-snapshot")
        if resume_snapshot:
            command.append("--resume-snapshot")
        for repository in snapshot_repositories:
            command += ["--snapshot-repository", repository]
        for package in snapshot_packages:
            command += ["--snapshot-package", package]
    if release:
        command += ["--release", release]
    if isinstance(arches, str):
        command += ["--arch", arches]
    elif isinstance(arches, list):
        for arch in arches:
            if not isinstance(arch, str):
                raise ValueError("arch must be a string or list of strings")
            command += ["--arch", arch]
    elif arches is not None:
        raise ValueError("arch must be a string or list of strings")
    elif device and device.architecture:
        command += ["--arch", device.architecture]
    targets = args.get("target")
    if isinstance(targets, str):
        command += ["--target", targets]
    elif isinstance(targets, list):
        for target in targets:
            if not isinstance(target, str):
                raise ValueError("target must be a string or list of strings")
            command += ["--target", target]
    elif targets is not None:
        raise ValueError("target must be a string or list of strings")
    if artifacts_dir:
        output = _safe_output_path(config, artifacts_dir)
        command += ["--artifacts-dir", str(output)]
    if _bool_arg(args, "all_arches", default=False):
        command.append("--all")
    if _bool_arg(args, "clean", default=False):
        command.append("--clean")
    if _bool_arg(args, "debug", default=False):
        command.append("--debug")
    permission_fallback = _enum_arg(
        args,
        "permission_fallback",
        ["error", "chmod"],
        default="error",
    )
    command += ["--permission-fallback", permission_fallback]
    pull_policy = _enum_arg(args, "pull_policy", ["always", "missing", "never"], default="always")
    if _bool_arg(args, "no_pull", default=False):
        pull_policy = "never"
    command += ["--pull-policy", pull_policy]
    if "no_vcs_apply" in args:
        command.append("--no-vcs-apply" if _bool_arg(args, "no_vcs_apply") else "--vcs-apply")
    if _bool_arg(args, "allow_untrusted_rpms", default=False):
        command.append("--allow-untrusted-rpms")
    for local_dir in _string_list_arg(args, "local_rpms_dir"):
        command += ["--local-rpms-dir", str(_safe_input_path(config, local_dir, allow_tmp=True))]
    if dry_run:
        command += ["--dry-run", "--json"]
    else:
        command.append("--quiet")
    try:
        project_path = build_sailfishos.resolve_project_dir(project_path)
    except SystemExit as error:
        raise ValueError(str(error)) from error
    command[command.index("--project-dir") + 1] = str(project_path)
    return command, project_path


def handle_build_preflight(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    command, project_path = _sailfish_build_command(config, args, dry_run=True)
    timeout = _int_arg(args, "timeout", default=120, minimum=1, maximum=600)
    result = run(command, timeout=timeout)
    structured: dict[str, Any] = {
        "project_path": str(project_path),
        "command": command,
        **result.summary_dict(),
    }
    if result.ok:
        try:
            plan = json.loads(result.stdout)
        except json.JSONDecodeError:
            return tool_error("build preflight returned invalid JSON", structured)
        if not isinstance(plan, dict):
            return tool_error("build preflight did not return a JSON object", structured)
        structured["plan"] = plan
        return ok_text(result.stdout.strip(), structured)
    return command_result("Sailfish build preflight", result, structured)


def handle_build_rpm(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    command, project_path = _sailfish_build_command(config, args)
    timeout = _int_arg(args, "timeout", default=3600, minimum=1, maximum=21600)
    if _bool_arg(args, "wait", default=False):
        return command_result("build Sailfish RPM", run(command, timeout=timeout))
    metadata_path = project_path / ".mb2" / build_sailfishos.BUILD_METADATA_NAME
    job = _start_background_command(
        "build Sailfish RPM",
        command,
        timeout=timeout,
        metadata_path=metadata_path,
    )
    text = "\n".join(
        [
            f"started build job {job['job_id']}",
            f"status: {job['status_path']}",
            f"log: {job['log_path']}",
            (
                "wait with sailfish_build_status "
                f"wait_seconds={MAX_MCP_WAIT_SECONDS} and lines=0"
            ),
        ]
    )
    return ok_text(text, _compact_build_status(job))


@_status_response
def handle_build_status(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    job_id = _optional_str(args, "job_id")
    lines = _int_arg(args, "lines", default=0, minimum=0, maximum=1000)
    wait_seconds = _int_arg(
        args,
        "wait_seconds",
        default=0,
        minimum=0,
        maximum=MAX_MCP_WAIT_SECONDS,
    )
    verbose = _bool_arg(args, "verbose", default=False)
    jobs_dir = _build_jobs_dir()
    if not job_id:
        jobs = []
        if jobs_dir.exists():
            for status_path in sorted(jobs_dir.glob("*/status.json"), key=lambda p: p.stat().st_mtime):
                if not _valid_local_job_id(status_path.parent.name):
                    continue
                status = _read_job_status(status_path)
                if status:
                    status = _with_supervisor_health(status, status_path.parent)
                    jobs.append(status if verbose else _compact_build_status(status))
        jobs = jobs[-20:]
        text = "\n".join(
            f"{job.get('job_id')}: {job.get('state')} {job.get('started_at', '')}"
            for job in jobs
        )
        return ok_text(text or "no build jobs found", {"jobs_dir": str(jobs_dir), "jobs": jobs})

    _validate_local_job_id(job_id)
    job_dir = _local_job_dir(jobs_dir, job_id)
    status_path = job_dir / "status.json"
    if not status_path.exists():
        return tool_error(f"unknown build job: {job_id}", {"jobs_dir": str(jobs_dir)})
    deadline = time.monotonic() + wait_seconds
    status = _read_job_status(status_path)
    if status:
        status = _with_supervisor_health(status, job_dir)
    while status and wait_seconds and not _job_is_terminal(status):
        if time.monotonic() >= deadline:
            break
        time.sleep(0.25)
        status = _read_job_status(status_path)
        if status:
            status = _with_supervisor_health(status, job_dir)
    if not status:
        return tool_error(f"could not read build job status: {job_id}")
    state = str(status.get("state") or "unknown")
    returncode = status.get("returncode")
    log_path = job_dir / "build.log"
    page = {}
    if "log_offset" in args:
        log_tail, page = _log_page(log_path, _int_arg(args, "log_offset", minimum=0, default=0),
                                  _int_arg(args, "max_bytes", default=6000, minimum=1, maximum=12000))
        log_kind = "page"
    elif lines:
        log_tail = _tail_file(log_path, lines)
        log_kind = "tail"
    elif state in {"failed", "timed_out"} or (
        state == "finished" and returncode not in (0, None)
    ):
        log_tail = _failure_excerpt_from_file(log_path)
        log_kind = "failure_excerpt"
    else:
        log_tail = ""
        log_kind = "none"
    text_lines = [
        f"job_id: {status.get('job_id')}",
        f"state: {state}",
        f"returncode: {returncode}",
        f"log: {log_path}",
    ]
    if status.get("failure_class"):
        text_lines.append(f"failure: {status.get('failure_class')}: {status.get('failure_message', '')}")
    artifacts = status.get("artifacts")
    if isinstance(artifacts, list) and artifacts:
        text_lines.append(f"artifacts: {len(artifacts)}")
        text_lines.extend(f"  {artifact}" for artifact in artifacts)
    if log_tail:
        text_lines += ["", log_tail]
    structured = dict(status) if verbose else _compact_build_status(status)
    structured.update(page)
    structured.update(
        log_included=bool(log_tail),
        log_kind=log_kind,
        log_chars=len(log_tail),
    )
    if verbose:
        structured["log_tail"] = log_tail
    return {
        "content": [{"type": "text", "text": "\n".join(text_lines)}],
        "structuredContent": structured,
        "isError": state in {"failed", "timed_out"} or (
            state == "finished" and returncode not in (0, None)
        ),
    }


def handle_build_cancel(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    job_id = _str_arg(args, "job_id")
    _validate_local_job_id(job_id)
    job_dir = _local_job_dir(_build_jobs_dir(), job_id)
    status_path = job_dir / "status.json"
    status = _read_job_status(status_path)
    if status is None:
        return tool_error(f"unknown build job: {job_id}")
    if _job_is_terminal(status):
        return ok_text(f"build job {job_id} is already {status.get('state')}", status)
    marker = job_dir / "cancel.requested"
    marker.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    structured = dict(status)
    structured["cancel_requested"] = True
    return ok_text(f"cancellation requested for build job {job_id}", structured)


def handle_android_build_hosts(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    text = "\n".join(
        (
            f"{name}{' (default)' if name == config.default_android_build_host else ''}: "
            f"{host.ssh_target} project={host.project_dir} state={host.state_dir}"
        )
        for name, host in sorted(config.android_build_hosts.items(), key=lambda item: item[0])
    )
    structured = {
        "default_android_build_host": config.default_android_build_host,
        "android_build_hosts": {
            name: host.public_dict()
            for name, host in config.android_build_hosts.items()
        },
    }
    return ok_text(text or "No configured Android build hosts", structured)


def handle_android_build(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    host = _android_build_host(config, args)
    project_dir_arg = _optional_str(args, "project_dir") or host.project_dir
    if not project_dir_arg:
        return tool_error(
            "project_dir is required; configure android_build_hosts.<host>.project_dir "
            "or pass project_dir"
        )
    project_dir = _remote_absolute_path(
        project_dir_arg,
        "project_dir",
    )
    state_dir = _remote_absolute_path(
        _optional_str(args, "state_dir") or host.state_dir,
        "state_dir",
    )
    shell_command = _str_arg(args, "shell_command")
    shell = _enum_arg(args, "shell", ["bash", "sh"], default="bash")
    timeout = _int_arg(args, "timeout", default=60, minimum=1, maximum=600)
    build_timeout = _int_arg(args, "build_timeout", default=0, minimum=0, maximum=86400)
    job_id = _optional_str(args, "job_id") or _new_android_build_job_id()
    _validate_remote_job_id(job_id)

    job_dir = str(PurePosixPath(state_dir) / job_id)
    log_path = str(PurePosixPath(job_dir) / "build.log")
    remote = _android_build_start_command(
        host=host,
        project_dir=project_dir,
        state_dir=state_dir,
        job_id=job_id,
        shell=shell,
        shell_command=shell_command,
        build_timeout=build_timeout,
    )
    result = run(_android_build_ssh_argv(config, host, remote), timeout=timeout)
    structured = {
        "host": host.public_dict(),
        "project_dir": project_dir,
        "state_dir": state_dir,
        "job_id": job_id,
        "job_dir": job_dir,
        "log_path": log_path,
        "shell": shell,
        "build_timeout": build_timeout,
    }
    if not result.ok:
        return command_result("start Android build", result, structured)

    text = "\n".join(
        [
            f"started Android build job {job_id} on {host.name}",
            f"host: {host.ssh_target}",
            f"project: {project_dir}",
            f"state: {job_dir}",
            f"log: {log_path}",
            (
                "wait with sailfish_android_build_status "
                f"wait_seconds={MAX_MCP_WAIT_SECONDS} and lines=0"
            ),
        ]
    )
    if result.stdout.strip():
        text += "\n\n" + result.stdout.strip()
    data = result.summary_dict()
    data.update(structured)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": data,
        "isError": False,
    }


@_status_response
def handle_android_build_status(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    host = _android_build_host(config, args)
    state_dir = _remote_absolute_path(
        _optional_str(args, "state_dir") or host.state_dir,
        "state_dir",
    )
    job_id = _optional_str(args, "job_id")
    lines = _int_arg(args, "lines", default=0, minimum=0, maximum=1000)
    wait_seconds = _int_arg(
        args,
        "wait_seconds",
        default=0,
        minimum=0,
        maximum=MAX_MCP_WAIT_SECONDS,
    )
    poll_interval = _int_arg(args, "poll_interval", default=5, minimum=1, maximum=30)
    verbose = _bool_arg(args, "verbose", default=False)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=600)
    started = time.monotonic()
    polls = 0

    if job_id:
        _validate_remote_job_id(job_id)
        remote = _android_build_status_command(
            state_dir,
            job_id,
            0 if wait_seconds else lines,
            include_command=verbose,
        )
        structured: dict[str, Any] = {
            "host": host.public_dict(),
            "state_dir": state_dir,
            "job_id": job_id,
        }
    else:
        remote = _android_build_list_command(state_dir)
        structured = {"host": host.public_dict(), "state_dir": state_dir}

    result = run(_android_build_ssh_argv(config, host, remote), timeout=min(timeout, wait_seconds) if wait_seconds else timeout)
    polls += 1
    if job_id:
        parsed = _parse_android_build_status(result.stdout)
        deadline = started + wait_seconds
        while result.ok and wait_seconds and not _android_status_is_terminal(parsed):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(poll_interval, remaining))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            remote = _android_build_status_command(
                state_dir,
                job_id,
                0,
                include_command=verbose,
            )
            result = run(_android_build_ssh_argv(config, host, remote), timeout=min(timeout, remaining))
            polls += 1
            parsed = _parse_android_build_status(result.stdout)

        state = parsed.get("state")
        returncode = parsed.get("returncode")
        failed = state == "timed_out" or (
            state == "finished" and returncode not in (0, None)
        )
        final_lines = lines or (80 if failed else 0)
        remaining = deadline - time.monotonic() if wait_seconds else timeout
        if result.ok and final_lines and (wait_seconds or lines == 0) and remaining > 0:
            remote = _android_build_status_command(
                state_dir,
                job_id,
                final_lines,
                include_command=verbose,
            )
            result = run(_android_build_ssh_argv(config, host, remote), timeout=min(timeout, remaining))
            polls += 1
            parsed = _parse_android_build_status(result.stdout)
            state = parsed.get("state")
            returncode = parsed.get("returncode")
            failed = state == "timed_out" or (
                state == "finished" and returncode not in (0, None)
            )
        if not verbose:
            parsed.pop("command", None)
        structured.update(parsed)
        structured["transport"] = (
            result.public_dict() if verbose else result.summary_dict()
        )
        structured.update(
            polls=polls,
            waited_seconds=round(time.monotonic() - started, 3),
            wait_expired=bool(
                wait_seconds and result.ok and not _android_status_is_terminal(parsed)
            ),
        )
        log_tail = _android_status_log_tail(result.stdout)
        if failed and log_tail and lines == 0:
            log_tail = _failure_excerpt(log_tail)
            log_kind = "failure_excerpt"
        elif log_tail:
            log_kind = "tail"
        else:
            log_kind = "none"
        structured.update(
            log_included=bool(log_tail),
            log_kind=log_kind,
            log_chars=len(log_tail),
        )
        text_lines = [
            f"job_id: {parsed.get('job_id') or job_id}",
            f"state: {state or 'unknown'}",
            f"returncode: {returncode}",
            f"log: {parsed.get('log_path') or ''}",
        ]
        if log_tail:
            text_lines += ["", log_tail]
        if verbose:
            structured["log_tail"] = log_tail
        return {
            "content": [{"type": "text", "text": "\n".join(text_lines)}],
            "structuredContent": structured,
            "isError": not result.ok or failed,
        }

    return command_result(
        "Android build status",
        result,
        {
            **structured,
            "polls": polls,
            "waited_seconds": round(time.monotonic() - started, 3),
            "wait_expired": False,
        },
        verbose=verbose,
    )


def handle_android_build_cancel(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    host = _android_build_host(config, args)
    state_dir = _remote_absolute_path(
        _optional_str(args, "state_dir") or host.state_dir,
        "state_dir",
    )
    job_id = _str_arg(args, "job_id")
    _validate_remote_job_id(job_id)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=600)
    remote = _android_build_cancel_command(state_dir, job_id)
    result = run(_android_build_ssh_argv(config, host, remote), timeout=timeout)
    return command_result(
        "cancel Android build",
        result,
        {"host": host.public_dict(), "state_dir": state_dir, "job_id": job_id},
    )


def _mcp_state_dir() -> Path:
    value = os.environ.get("SAILFISH_DEVEL_MCP_STATE_DIR")
    if value:
        return Path(value).expanduser()
    value = os.environ.get("SAILFISH_DEVEL_MCP_LOG_DIR")
    if value:
        return Path(value).expanduser()
    value = os.environ.get("XDG_STATE_HOME")
    if value:
        return Path(value).expanduser() / "sailfish-devel-mcp"
    value = os.environ.get("HOME")
    if value:
        return Path(value).expanduser() / ".local" / "state" / "sailfish-devel-mcp"
    return Path("/tmp") / "sailfish-devel-mcp"


def _build_jobs_dir() -> Path:
    return _mcp_state_dir() / "builds"


def _device_command_jobs_dir() -> Path:
    return _mcp_state_dir() / "device-commands"


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _valid_local_job_id(job_id: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", job_id))


def _validate_local_job_id(job_id: str) -> None:
    if not _valid_local_job_id(job_id):
        raise ValueError("job_id contains unsupported characters")


def _local_job_dir(jobs_dir: Path, job_id: str) -> Path:
    _validate_local_job_id(job_id)
    root = jobs_dir.resolve(strict=False)
    job_dir = (root / job_id).resolve(strict=False)
    try:
        job_dir.relative_to(root)
    except ValueError as exc:  # Defensive in case validation changes later.
        raise ValueError("job_id escapes the jobs directory") from exc
    return job_dir


def _new_local_job(jobs_dir: Path, prefix: str) -> tuple[str, Path]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,31}", prefix):
        raise ValueError("job prefix contains unsupported characters")
    jobs_dir.mkdir(parents=True, exist_ok=True)
    for _ in range(3):
        now = datetime.now(timezone.utc)
        job_id = f"{prefix}-{now.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:16]}"
        job_dir = _local_job_dir(jobs_dir, job_id)
        try:
            job_dir.mkdir(mode=0o700)
        except FileExistsError:
            continue
        return job_id, job_dir
    raise RuntimeError("could not allocate a unique job directory")


def _process_start_time(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    marker = stat.rfind(") ")
    if marker < 0:
        return None
    fields = stat[marker + 2 :].split()
    return fields[19] if len(fields) > 19 else None


def _job_is_terminal(status: dict[str, Any]) -> bool:
    return status.get("state") in {"finished", "failed", "timed_out", "cancelled"}


def _with_supervisor_health(status: dict[str, Any], job_dir: Path | None = None) -> dict[str, Any]:
    if status.get("backend") == "companion":
        return status
    if _job_is_terminal(status):
        return status
    pid = status.get("supervisor_pid")
    expected_start = status.get("supervisor_start_time")
    if not isinstance(pid, int) and job_dir is not None:
        sidecar = _read_job_status(job_dir / "supervisor.json")
        if sidecar:
            pid = sidecar.get("pid")
            expected_start = sidecar.get("start_time")
    if not isinstance(pid, int):
        return status
    actual_start = _process_start_time(pid)
    if actual_start is None or (expected_start and actual_start != expected_start):
        result = dict(status)
        result.update(
            state="failed",
            failure_class="supervisor-lost",
            failure_message="job supervisor is no longer running",
        )
        return result
    return status


def _start_background_command(
    label: str,
    command: list[str],
    *,
    timeout: int,
    metadata_path: Path | None = None,
    jobs_dir: Path | None = None,
    job_prefix: str = "build",
    log_name: str = "build.log",
    status_fields: dict[str, Any] | None = None,
    request: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _reap_background_supervisors()
    now = datetime.now(timezone.utc)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", log_name):
        raise ValueError("job log name contains unsupported characters")
    job_id, job_dir = _new_local_job(jobs_dir or _build_jobs_dir(), job_prefix)
    if request is not None:
        request_path = job_dir / "request.json"
        _write_json_atomic(request_path, request)
        command = [*command, str(request_path)]
        if request.get("operation") == "device_setup":
            metadata_path = job_dir / "result.json"
    log_path = job_dir / log_name
    status_path = job_dir / "status.json"
    supervisor_status_path = job_dir / "supervisor.json"
    cancel_path = job_dir / "cancel.requested"
    try:
        metadata_mtime_ns = metadata_path.stat().st_mtime_ns if metadata_path else None
    except OSError:
        metadata_mtime_ns = None
    status = dict(status_fields or {})
    status.update(
        {
            "job_id": job_id,
            "label": label,
            "state": "starting",
            "argv": command,
            "timeout": timeout,
            "created_at": now.isoformat(),
            "status_path": str(status_path),
            "log_path": str(log_path),
            "metadata_path": str(metadata_path) if metadata_path else None,
            "metadata_mtime_ns": metadata_mtime_ns,
        }
    )
    _write_json_atomic(status_path, status)

    supervisor = r"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_status(path: Path, data: dict[str, object]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def process_start_time(pid: int) -> str | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    marker = stat.rfind(") ")
    fields = stat[marker + 2:].split() if marker >= 0 else []
    return fields[19] if len(fields) > 19 else None


def group_has_live_processes(pgid: int) -> bool:
    # killpg(..., 0) also sees zombies, which cannot execute or write artifacts.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8")
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        fields = stat[stat.rfind(") ") + 2:].split()
        if len(fields) > 2 and int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
            return True
    return False


def terminate(process: subprocess.Popen[str], log, reason: str) -> int:
    log.write(f"[{now()}] {reason}; terminating process group {process.pid}\n")
    log.flush()
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 30
    while group_has_live_processes(process.pid):
        process.poll()
        if time.monotonic() >= deadline:
            log.write(f"[{now()}] process group did not exit; killing {process.pid}\n")
            log.flush()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            kill_deadline = time.monotonic() + 5
            while group_has_live_processes(process.pid):
                process.poll()
                if time.monotonic() >= kill_deadline:
                    raise RuntimeError("process group remains alive after SIGKILL")
                time.sleep(0.05)
            break
        time.sleep(0.05)
    return process.wait()


status_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])
cancel_path = Path(sys.argv[3])
timeout = int(sys.argv[4])
metadata_arg = sys.argv[5]
metadata_path = Path(metadata_arg) if metadata_arg else None
command = sys.argv[6:]

status = json.loads(status_path.read_text(encoding="utf-8"))
status["supervisor_pid"] = os.getpid()
status["supervisor_start_time"] = process_start_time(os.getpid())
status["started_at"] = now()
log_path.parent.mkdir(parents=True, exist_ok=True)

with log_path.open("a", encoding="utf-8", errors="replace") as log:
    log.write(f"[{now()}] starting {' '.join(command)}\n")
    log.flush()
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
            close_fds=True,
        )
        status["pid"] = process.pid
        status["state"] = "running"
        write_status(status_path, status)

        deadline = time.monotonic() + timeout
        timed_out = False
        cancelled = False
        returncode = None
        while True:
            returncode = process.poll()
            if returncode is not None:
                break
            if cancel_path.exists():
                cancelled = True
                returncode = terminate(process, log, "cancellation requested")
                break
            if time.monotonic() >= deadline:
                timed_out = True
                returncode = terminate(process, log, f"timeout after {timeout}s")
                break
            time.sleep(0.25)

        status["state"] = (
            "cancelled" if cancelled else "timed_out" if timed_out else "finished" if returncode == 0 else "failed"
        )
        status["returncode"] = returncode
        status["timed_out"] = timed_out
        status["cancelled"] = cancelled
        status["finished_at"] = now()
        baseline_mtime = status.get("metadata_mtime_ns")
        try:
            metadata_stat = metadata_path.stat() if metadata_path else None
        except OSError:
            metadata_stat = None
        if (
            metadata_path
            and metadata_stat
            and metadata_stat.st_size <= 1024 * 1024
            and (baseline_mtime is None or metadata_stat.st_mtime_ns > baseline_mtime)
        ):
            try:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                metadata = None
            if isinstance(metadata, dict):
                status["build_metadata"] = metadata
                if status.get("job_kind") == "device_setup":
                    status["device_setup"] = metadata.get("structuredContent", {})
                    status["result_path"] = str(metadata_path)
                status["artifacts"] = metadata.get("rpms", [])
                if metadata.get("failure_class"):
                    status["failure_class"] = metadata["failure_class"]
                if metadata.get("failure_message"):
                    status["failure_message"] = metadata["failure_message"]
        write_status(status_path, status)
        log.write(
            f"[{now()}] finished state={status['state']} returncode={returncode} "
            f"timed_out={timed_out} cancelled={cancelled}\n"
        )
    except BaseException as error:
        if process is not None and process.poll() is None:
            try:
                terminate(process, log, "supervisor failure")
            except BaseException as terminate_error:
                log.write(
                    f"[{now()}] failed to terminate process group: "
                    f"{type(terminate_error).__name__}: {terminate_error}\n"
                )
        status["state"] = "failed"
        status["failure_class"] = "supervisor"
        status["failure_message"] = f"{type(error).__name__}: {error}"
        status["finished_at"] = now()
        write_status(status_path, status)
        log.write(f"[{now()}] supervisor failed: {type(error).__name__}: {error}\n")
        raise
"""
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                supervisor,
                str(status_path),
                str(log_path),
                str(cancel_path),
                str(timeout),
                str(metadata_path) if metadata_path else "",
                *command,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except BaseException as error:
        status.update(
            state="failed",
            failure_class="supervisor-start",
            failure_message=f"{type(error).__name__}: {error}",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        _write_json_atomic(status_path, status)
        raise
    _write_json_atomic(
        supervisor_status_path,
        {"pid": process.pid, "start_time": _process_start_time(process.pid)},
    )
    _BACKGROUND_SUPERVISORS[process.pid] = process
    response = dict(status)
    response["supervisor_pid"] = process.pid
    return response


def _read_job_status(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if _job_is_terminal(data):
        pid = data.get("supervisor_pid")
        supervisor = _BACKGROUND_SUPERVISORS.get(pid) if isinstance(pid, int) else None
        if supervisor is not None:
            try:
                supervisor.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            else:
                _BACKGROUND_SUPERVISORS.pop(pid, None)
    return data


def _tail_file(path: Path, lines: int, max_bytes: int = 12000) -> str:
    if lines <= 0:
        return ""
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            start = max(0, handle.tell() - max_bytes)
            handle.seek(start)
            text = handle.read(max_bytes).decode("utf-8", errors="replace")
    except OSError:
        return ""
    selected = "\n".join(text.splitlines()[-lines:])
    return ("[tail truncated]\n" if start else "") + selected


def _log_page(path: Path, offset: int, max_bytes: int) -> tuple[str, dict[str, Any]]:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        if offset > size:
            raise ValueError("log_offset exceeds current log size; restart at zero")
        handle.seek(offset)
        data = handle.read(max_bytes)
    return data.decode("utf-8", errors="replace"), {"next_offset": offset + len(data),
                                                  "eof": offset + len(data) >= size}


def _compact_build_status(status: dict[str, Any]) -> dict[str, Any]:
    fields = ("job_id", "job_kind", "state", "returncode", "log_path", "status_path",
              "failure_class", "failure_message", "artifacts", "device_setup", "result_path")
    data = {field: status[field] for field in fields if field in status}
    metadata = status.get("build_metadata") or {}
    for key in ("helper_version", "backend", "release", "duration_seconds", "rpmlint", "provenance", "artifact_checksums"):
        if key in metadata:
            data[key] = metadata[key]
    if metadata.get("builds"):
        data["builds"] = [{key: build[key] for key in (
            "arch", "target", "base_target", "status", "dependency_diagnostics") if key in build}
            for build in metadata["builds"]]
    return data


def _compact_device_command_status(status: dict[str, Any]) -> dict[str, Any]:
    fields = ("job_id", "job_kind", "device", "state", "returncode", "log_path",
              "status_path", "failure_class", "failure_message", "backend", "remote_log_path", "remote_status_path")
    return {field: status[field] for field in fields if field in status}


def _failure_excerpt_from_file(
    path: Path,
    *,
    max_lines: int = 80,
    max_chars: int = 6000,
) -> str:
    return _failure_excerpt(_tail_file(path, 1000, max_bytes=64000),
                            max_lines=max_lines, max_chars=max_chars)


def _failure_excerpt(text: str, *, max_lines: int = 80, max_chars: int = 6000) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    markers = (
        "error:",
        "failed",
        "fatal:",
        "undefined reference",
        "no such file",
        "not found",
        "command not found",
    )
    matching = [
        index
        for index, line in enumerate(lines)
        if any(marker in line.lower() for marker in markers)
    ]
    if matching:
        last = matching[-1]
        start = max(0, last - 20)
        end = min(len(lines), last + 20)
        selected = lines[start:end]
    else:
        selected = lines[-max_lines:]
    selected = selected[-max_lines:]
    excerpt = "\n".join(selected)
    if len(excerpt) > max_chars:
        excerpt = excerpt[-max_chars:]
        excerpt = "[failure excerpt truncated]\n" + excerpt
    return excerpt


def _job_receipt(job: dict[str, Any]) -> dict[str, Any]:
    return ok_text(f"started {job['job_id']}; use sailfish_build_status or the jobs CLI waiter",
                   _compact_build_status(job))


def _start_operation(config, args, operation, label, timeout):
    job = _start_background_command(
        label, [sys.executable, "-m", "sailfish_devel_mcp.jobs", "run-operation"],
        timeout=timeout, request={"config": config.public_dict(), "arguments": args,
                                  "operation": operation},
        status_fields={"job_kind": operation},
    )
    return _job_receipt(job)


def handle_obs_watch(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    project = _str_arg(args, "project")
    package = _optional_str(args, "package")
    server, alias = _obs_server_selection(config, args)
    command = ["osc", "-A", alias] if alias else ["osc"]
    command += ["results", "--watch", "--fail-on-error", project]
    if package:
        command.append(package)
    timeout = _int_arg(args, "timeout", default=21600, minimum=1, maximum=86400)
    return _job_receipt(_start_background_command(
        "watch OBS results", command, timeout=timeout,
        status_fields={"job_kind": "obs_watch", "project": project, "package": package,
                       "server": server, "api_alias": alias}))


def handle_doctor(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    helper = config.paths.build_sailfishos
    report = build_sailfishos.doctor(config.paths.local_sdk)
    report["tools"].update({name: bool(shutil.which(name)) for name in ("python3", "sh", "bash", "grep")})
    manifest_path = Path(build_sailfishos.__file__).with_name("build-helper.json")
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    digest = hashlib.sha256(helper.read_bytes()).hexdigest() if helper.is_file() else None
    report["host_runtime"] = _host_runtime_identity()
    report.update(helper_exists=helper.is_file(), helper_matches_vendor=digest == manifest.get("sha256"),
                  configured_helper=str(helper), vendored_source=manifest,
                  device_count=len(config.devices), android_host_count=len(config.android_build_hosts),
                  config_file=str(config.path) if config.path else None,
                  ssh_config_exists=bool(config.paths.ssh_config and config.paths.ssh_config.is_file()))
    return ok_text(json.dumps(report, separators=(",", ":")), report)


def handle_sdk_refresh_metadata(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    local_sdk = _local_sdk_path(config, args)
    if local_sdk is None:
        return tool_error("paths.local_sdk or local_sdk argument is required")
    target = _local_sdk_target(config, args, local_sdk)
    if target is None:
        return tool_error("target, arch, or a device with architecture is required")
    main_target = build_sailfishos.sdk_refresh_target(local_sdk, target)
    timeout = _int_arg(args, "timeout", default=600, minimum=1, maximum=3600)
    command = build_sailfishos.sdk_refresh_command(local_sdk, main_target, _bool_arg(args, "force"))
    if not _bool_arg(args, "wait", default=False):
        job = _start_background_command("refresh SDK metadata", command, timeout=timeout,
                                        status_fields={"job_kind": "sdk_refresh", "target": main_target})
        return _job_receipt(job)
    result = run(command, timeout=timeout)
    return command_result(
        "refresh local SDK metadata",
        result,
        {
            "local_sdk": str(local_sdk),
            "target": target,
            "main_target": main_target,
        },
    )


def handle_obs_results(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    project = _str_arg(args, "project")
    package = _optional_str(args, "package")
    server, api_alias = _obs_server_selection(config, args)
    command = ["osc"]
    if api_alias:
        command += ["-A", api_alias]
    command += ["results", project]
    if package:
        command.append(package)
    timeout = _int_arg(args, "timeout", default=60, minimum=1, maximum=600)
    wait_seconds = _int_arg(
        args,
        "wait_seconds",
        default=0,
        minimum=0,
        maximum=MAX_MCP_WAIT_SECONDS,
    )
    poll_interval = _int_arg(args, "poll_interval", default=5, minimum=1, maximum=30)
    verbose = _bool_arg(args, "verbose", default=False)
    started = time.monotonic()
    deadline = started + wait_seconds
    polls = 0
    result = run(command, timeout=min(timeout, max(0.001, deadline - time.monotonic())) if wait_seconds else timeout)
    polls += 1
    while result.ok and wait_seconds and _obs_results_pending(result.stdout):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(poll_interval, remaining))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        result = run(command, timeout=min(timeout, remaining))
        polls += 1
    pending = result.ok and _obs_results_pending(result.stdout)
    return command_result(
        "OBS results",
        result,
        {
            "server": server,
            "api_alias": api_alias,
            "pending": pending,
            "polls": polls,
            "waited_seconds": round(time.monotonic() - started, 3),
            "wait_expired": bool(wait_seconds and pending),
        },
        verbose=verbose,
    )


def handle_obs_buildlog(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    project = _str_arg(args, "project")
    package = _str_arg(args, "package")
    repository = _str_arg(args, "repository")
    arch = _str_arg(args, "arch")
    server, api_alias = _obs_server_selection(config, args)
    timeout = _int_arg(args, "timeout", default=90, minimum=1, maximum=1800)
    nostream = _bool_arg(args, "nostream", default=True)
    lines = _int_arg(args, "lines", default=120, minimum=0, maximum=5000)
    verbose = _bool_arg(args, "verbose", default=False)
    command = ["osc"]
    if api_alias:
        command += ["-A", api_alias]
    if nostream:
        path = "/build/{}/{}/{}/{}/_log?nostream=1".format(
            quote(project, safe=""),
            quote(repository, safe=""),
            quote(arch, safe=""),
            quote(package, safe=""),
        )
        command += ["api", path]
    else:
        command += ["remotebuildlog", project, package, repository, arch]
    result = run(command, timeout=timeout)
    response_result = result
    if not verbose and lines:
        response_result = CommandResult(
            result.argv,
            result.returncode,
            _tail_text(result.stdout, lines=lines, max_chars=4000),
            _tail_text(result.stderr, lines=lines, max_chars=2000),
        )
    return command_result(
        "OBS build log",
        response_result,
        {
            "server": server,
            "api_alias": api_alias,
            "source_stdout_chars": len(result.stdout),
            "source_stderr_chars": len(result.stderr),
            "lines": lines,
        },
        verbose=verbose,
    )


def _obs_results_pending(stdout: str) -> bool:
    pending_codes = {
        "blocked",
        "building",
        "dispatching",
        "finished",
        "pending",
        "publishing",
        "scheduled",
        "signing",
    }
    words = set(re.findall(r"[a-z_]+", stdout.lower()))
    return bool(words & pending_codes)


def _tail_text(text: str, *, lines: int, max_chars: int) -> str:
    selected = "\n".join(text.splitlines()[-lines:])
    if len(selected) <= max_chars:
        return selected
    return "[tail truncated]\n" + selected[-max_chars:]


def handle_repo_status(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    path = _safe_input_path(config, _optional_str(args, "path") or ".", allow_tmp=False)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=120)
    result = run(["git", "status", "--short", "--branch"], cwd=path, timeout=timeout)
    return command_result("git status", result, {"path": str(path)})


def handle_repo_find(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    path = _safe_input_path(config, _optional_str(args, "path") or ".", allow_tmp=False)
    query = _str_arg(args, "query")
    max_count = _int_arg(args, "max_count", default=100, minimum=1, maximum=1000)
    fixed_strings = _bool_arg(args, "fixed_strings", default=True)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=300)

    if shutil.which("rg"):
        command = ["rg", "--line-number", "--hidden", "--glob", "!.git"]
        if fixed_strings:
            command.append("--fixed-strings")
        command += ["--max-count", str(max_count), "--", query, str(path)]
    else:
        command = ["grep", "-r", "-n"]
        if fixed_strings:
            command.append("-F")
        command += ["--", query, str(path)]
    result = run(command, timeout=timeout)
    if result.returncode == 1 and not result.stdout:
        return ok_text("no matches", {"path": str(path), "query": query, "matches": 0})
    return command_result("repo find", result, {"path": str(path), "query": query})


def handle_spec_summary(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    path_arg = _optional_str(args, "spec_path")
    if path_arg:
        spec_path = _safe_input_path(config, path_arg, allow_tmp=False)
    else:
        repo = _safe_input_path(config, _optional_str(args, "repo_path") or ".", allow_tmp=False)
        specs = sorted((repo / "rpm").glob("*.spec"))
        if not specs:
            return tool_error(f"no rpm/*.spec file found under {repo}")
        spec_path = _safe_input_path(config, str(specs[0]), allow_tmp=False)

    if not spec_path.exists():
        return tool_error(f"spec file does not exist: {spec_path}")
    data = _parse_spec(spec_path)
    text_lines = [f"{key}: {value}" for key, value in data.items() if value]
    return ok_text("\n".join(text_lines), {"spec_path": str(spec_path), "summary": data})


def handle_qml_find_translations(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    path = _safe_input_path(config, _optional_str(args, "path") or ".", allow_tmp=False)
    timeout = _int_arg(args, "timeout", default=30, minimum=1, maximum=300)
    if not shutil.which("rg"):
        return tool_error("rg is required for qml_find_translations")
    command = [
        "rg",
        "--line-number",
        "--glob",
        "*.qml",
        r"qsTrId|//%|//:",
        str(path),
    ]
    result = run(command, timeout=timeout)
    if result.returncode == 1 and not result.stdout:
        return ok_text("no QML translation markers found", {"path": str(path), "matches": 0})
    return command_result("QML translations", result, {"path": str(path)})


def handle_qml_check_translator_ternaries(config: Config, args: dict[str, Any]) -> dict[str, Any]:
    path = _safe_input_path(config, _optional_str(args, "path") or ".", allow_tmp=False)
    files = [path] if path.is_file() and path.suffix == ".qml" else sorted(path.rglob("*.qml"))
    findings: list[dict[str, Any]] = []
    for qml in files:
        if ".git" in qml.parts:
            continue
        qml = _safe_input_path(config, str(qml), allow_tmp=False)
        try:
            lines = qml.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        findings.extend({"path": str(qml), **finding}
                        for finding in ternary_translation_findings("\n".join(lines)))
    if not findings:
        return ok_text("no ternary translation issues found", {"path": str(path), "findings": []})
    text = "\n".join(
        f"{item['path']}:{item['line']}: {item['message']}\n  {item['text']}"
        for item in findings
    )
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": {"path": str(path), "findings": findings},
        "isError": True,
    }


def _run_device(config, device, command, *, timeout, user=False, extra=None):
    from .companion_host import routed
    return routed(config, device, command, timeout=timeout, user=user, extra=extra,
                  fallback=remote_command(command))


def _run_ssh(
    config: Config,
    device: DeviceConfig,
    command: list[str],
    *,
    timeout: int,
) -> CommandResult:
    return run(
        ssh_argv(device, config.paths.ssh_config, remote_command(command)),
        timeout=timeout,
    )


def _device_user_session_argv(
    config: Config,
    device: DeviceConfig,
    command: list[str],
    *,
    run_as_user: bool,
) -> list[str]:
    session_command = user_bus_env(device) + command
    remote = remote_command(session_command)
    if run_as_user:
        remote = _run_as_user_command(device, remote)
    return ssh_argv(device, config.paths.ssh_config, remote)


def _android_build_host(config: Config, args: dict[str, Any]) -> AndroidBuildHostConfig:
    return config.android_build_host(_optional_str(args, "host"))


def _android_build_ssh_argv(
    config: Config,
    host: AndroidBuildHostConfig,
    remote: str,
) -> list[str]:
    argv = ["ssh"]
    if config.paths.ssh_config:
        argv += ["-F", str(config.paths.ssh_config)]
    argv += ["--", host.ssh_target, remote]
    return argv


def _new_android_build_job_id() -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"android-{now}-{uuid.uuid4().hex[:16]}"


def _validate_remote_job_id(job_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", job_id):
        raise ValueError("job_id contains unsupported characters")


def _remote_absolute_path(value: str, name: str) -> str:
    if "\0" in value or "\n" in value:
        raise ValueError(f"{name} contains unsupported characters")
    if not value.startswith("/"):
        raise ValueError(f"{name} must be an absolute remote path")
    return value


def _new_remote_rpm_dir() -> str:
    now = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    return f"/tmp/sailfish-devel-mcp-rpms-{now}-{uuid.uuid4().hex[:16]}"


def _android_build_start_command(
    *,
    host: AndroidBuildHostConfig,
    project_dir: str,
    state_dir: str,
    job_id: str,
    shell: str,
    shell_command: str,
    build_timeout: int,
) -> str:
    job_dir = str(PurePosixPath(state_dir) / job_id)
    log_path = str(PurePosixPath(job_dir) / "build.log")
    run_path = str(PurePosixPath(job_dir) / "run.sh")
    command_path = str(PurePosixPath(job_dir) / "command")
    pid_path = str(PurePosixPath(job_dir) / "pid")
    process_start_path = str(PurePosixPath(job_dir) / "process_start")
    created_at_path = str(PurePosixPath(job_dir) / "created_at")
    started_at_path = str(PurePosixPath(job_dir) / "started_at")
    finished_at_path = str(PurePosixPath(job_dir) / "finished_at")
    returncode_path = str(PurePosixPath(job_dir) / "returncode")
    timed_out_path = str(PurePosixPath(job_dir) / "timed_out")
    watchdog_pid_path = str(PurePosixPath(job_dir) / "watchdog_pid")
    watchdog_start_path = str(PurePosixPath(job_dir) / "watchdog_start")
    run_script = f"""#!/bin/sh
set +e
project_dir={shlex.quote(project_dir)}
log_path={shlex.quote(log_path)}
started_at_path={shlex.quote(started_at_path)}
finished_at_path={shlex.quote(finished_at_path)}
returncode_path={shlex.quote(returncode_path)}
host_name={shlex.quote(host.name)}
shell_bin={shlex.quote(shell)}
shell_command={shlex.quote(shell_command)}
build_timeout={build_timeout}
timed_out_path={shlex.quote(timed_out_path)}
watchdog_pid_path={shlex.quote(watchdog_pid_path)}
watchdog_start_path={shlex.quote(watchdog_start_path)}

date -Is > "$started_at_path"
printf '[%s] starting Android build on %s\\n' "$(date -Is)" "$host_name" >> "$log_path"
printf '[%s] project_dir=%s\\n' "$(date -Is)" "$project_dir" >> "$log_path"
printf '[%s] command=%s\\n' "$(date -Is)" "$shell_command" >> "$log_path"

cd "$project_dir"
cd_rc=$?
if [ "$cd_rc" -ne 0 ]; then
    printf '[%s] failed to cd to %s\\n' "$(date -Is)" "$project_dir" >> "$log_path"
    printf '%s\\n' "$cd_rc" > "$returncode_path"
    date -Is > "$finished_at_path"
    exit "$cd_rc"
fi

if [ "$build_timeout" -gt 0 ]; then
    setsid sh -c '
        sleep "$1"
        if kill -0 "$2" 2>/dev/null; then
            date -Is > "$3"
            kill -TERM -"$2" 2>/dev/null || true
            attempts=0
            while [ "$attempts" -lt 30 ]; do
                sleep 1
                if ! kill -0 -"$2" 2>/dev/null; then
                    exit 0
                fi
                attempts=$((attempts + 1))
            done
            kill -KILL -"$2" 2>/dev/null || true
        fi
    ' android-build-watchdog "$build_timeout" "$$" "$timed_out_path" \
        >/dev/null 2>&1 </dev/null &
    watchdog_pid=$!
    printf '%s\n' "$watchdog_pid" > "$watchdog_pid_path"
    sed 's/.*) //' "/proc/$watchdog_pid/stat" 2>/dev/null | cut -d' ' -f20 > "$watchdog_start_path" || true
else
    watchdog_pid=
fi

"$shell_bin" -lc "$shell_command" >> "$log_path" 2>&1
rc=$?
if [ -n "$watchdog_pid" ]; then
    if [ -f "$timed_out_path" ]; then
        rc=124
    else
        kill "$watchdog_pid" 2>/dev/null || true
        wait "$watchdog_pid" 2>/dev/null || true
    fi
fi
printf '%s\\n' "$rc" > "$returncode_path"
date -Is > "$finished_at_path"
printf '[%s] finished returncode=%s\\n' "$(date -Is)" "$rc" >> "$log_path"
exit "$rc"
"""
    encoded_run_script = base64.b64encode(run_script.encode("utf-8")).decode("ascii")
    script = f"""
set -eu
state_dir={shlex.quote(state_dir)}
job_id={shlex.quote(job_id)}
job_dir={shlex.quote(job_dir)}
run_path={shlex.quote(run_path)}
log_path={shlex.quote(log_path)}
command_path={shlex.quote(command_path)}
pid_path={shlex.quote(pid_path)}
process_start_path={shlex.quote(process_start_path)}
created_at_path={shlex.quote(created_at_path)}
umask 077
mkdir -p "$state_dir"
if ! mkdir "$job_dir"; then
    echo "job already exists: $job_id" >&2
    exit 2
fi
printf '%s' {shlex.quote(encoded_run_script)} | base64 -d > "$run_path"
chmod +x "$run_path"
: > "$log_path"
printf '%s\\n' {shlex.quote(shell_command)} > "$command_path"
date -Is > "$created_at_path"
nohup setsid "$run_path" >/dev/null 2>&1 </dev/null &
pid=$!
sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20 > "$process_start_path" || true
printf '%s\\n' "$pid" > "$pid_path"
printf 'job_id: %s\\n' "$job_id"
printf 'pid: %s\\n' "$pid"
printf 'host: %s\\n' {shlex.quote(host.name)}
printf 'project_dir: %s\\n' {shlex.quote(project_dir)}
printf 'job_dir: %s\\n' "$job_dir"
printf 'log_path: %s\\n' "$log_path"
"""
    return remote_command(["sh", "-lc", script])


def _android_build_list_command(state_dir: str) -> str:
    script = f"""
set -eu
state_dir={shlex.quote(state_dir)}
if [ ! -d "$state_dir" ]; then
    echo "no android build jobs found"
    exit 0
fi
output=$(
    for job_dir in "$state_dir"/*; do
        [ -d "$job_dir" ] || continue
        job_id=${{job_dir##*/}}
        pid=$(cat "$job_dir/pid" 2>/dev/null || true)
        expected_start=$(cat "$job_dir/process_start" 2>/dev/null || true)
        actual_start=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20 || true)
        returncode=$(cat "$job_dir/returncode" 2>/dev/null || true)
        cancel_requested=$(cat "$job_dir/cancel_requested" 2>/dev/null || true)
        timed_out=$(cat "$job_dir/timed_out" 2>/dev/null || true)
        created_at=$(cat "$job_dir/created_at" 2>/dev/null || true)
        started_at=$(cat "$job_dir/started_at" 2>/dev/null || true)
        timestamp=${{started_at:-$created_at}}
        if [ -n "$timed_out" ]; then
            state=timed_out
        elif [ -n "$returncode" ]; then
            state=finished
        elif [ -n "$cancel_requested" ] && [ "$actual_start" != "$expected_start" ]; then
            state=cancelled
        elif [ -n "$pid" ] && [ -n "$expected_start" ] && [ "$actual_start" = "$expected_start" ] && kill -0 "$pid" 2>/dev/null; then
            if [ -n "$cancel_requested" ]; then state=cancelling; else state=running; fi
        elif [ -n "$pid" ]; then
            state=unknown
        else
            state=starting
        fi
        printf '%s\\t%s: %s returncode=%s pid=%s\\n' "$timestamp" "$job_id" "$state" "$returncode" "$pid"
    done | sort | tail -n 20 | cut -f2-
)
if [ -n "$output" ]; then
    printf '%s\\n' "$output"
else
    echo "no android build jobs found"
fi
"""
    return remote_command(["sh", "-lc", script])


def _android_build_status_command(
    state_dir: str,
    job_id: str,
    lines: int,
    *,
    include_command: bool = False,
) -> str:
    job_dir = str(PurePosixPath(state_dir) / job_id)
    log_path = str(PurePosixPath(job_dir) / "build.log")
    command_output = "printf 'command: %s\\n' \"$command\"" if include_command else ":"
    script = f"""
set -eu
job_id={shlex.quote(job_id)}
job_dir={shlex.quote(job_dir)}
log_path={shlex.quote(log_path)}
lines={lines}
if [ ! -d "$job_dir" ]; then
    echo "unknown android build job: $job_id" >&2
    exit 2
fi
pid=$(cat "$job_dir/pid" 2>/dev/null || true)
expected_start=$(cat "$job_dir/process_start" 2>/dev/null || true)
actual_start=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20 || true)
watchdog_pid=$(cat "$job_dir/watchdog_pid" 2>/dev/null || true)
watchdog_expected_start=$(cat "$job_dir/watchdog_start" 2>/dev/null || true)
watchdog_actual_start=$(sed 's/.*) //' "/proc/$watchdog_pid/stat" 2>/dev/null | cut -d' ' -f20 || true)
returncode=$(cat "$job_dir/returncode" 2>/dev/null || true)
cancel_requested=$(cat "$job_dir/cancel_requested" 2>/dev/null || true)
timed_out=$(cat "$job_dir/timed_out" 2>/dev/null || true)
created_at=$(cat "$job_dir/created_at" 2>/dev/null || true)
started_at=$(cat "$job_dir/started_at" 2>/dev/null || true)
finished_at=$(cat "$job_dir/finished_at" 2>/dev/null || true)
command=$(cat "$job_dir/command" 2>/dev/null || true)
if [ -n "$timed_out" ]; then
    state=timed_out
elif [ -n "$returncode" ]; then
    state=finished
elif [ -n "$cancel_requested" ] && [ "$actual_start" != "$expected_start" ]; then
    state=cancelled
elif [ -n "$pid" ] && [ -n "$expected_start" ] && [ "$actual_start" = "$expected_start" ] && kill -0 "$pid" 2>/dev/null; then
    if [ -n "$cancel_requested" ]; then state=cancelling; else state=running; fi
elif [ -n "$pid" ]; then
    state=unknown
else
    state=starting
fi
printf 'job_id: %s\\n' "$job_id"
printf 'state: %s\\n' "$state"
printf 'returncode: %s\\n' "$returncode"
printf 'pid: %s\\n' "$pid"
printf 'created_at: %s\\n' "$created_at"
printf 'started_at: %s\\n' "$started_at"
printf 'finished_at: %s\\n' "$finished_at"
printf 'job_dir: %s\\n' "$job_dir"
printf 'log_path: %s\\n' "$log_path"
{command_output}
if [ "$lines" -gt 0 ] && [ -f "$log_path" ]; then
    printf '\\n'
    tail -n "$lines" "$log_path"
fi
"""
    return remote_command(["sh", "-lc", script])


def _parse_android_build_status(stdout: str) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for line in stdout.splitlines():
        if ": " not in line:
            continue
        key, value = line.split(": ", 1)
        if key not in {
            "job_id",
            "state",
            "returncode",
            "pid",
            "created_at",
            "started_at",
            "finished_at",
            "job_dir",
            "log_path",
            "command",
        }:
            continue
        if key in {"returncode", "pid"} and value:
            try:
                fields[key] = int(value)
            except ValueError:
                fields[key] = value
        else:
            fields[key] = value or None
    return fields


def _android_status_is_terminal(status: dict[str, Any]) -> bool:
    return status.get("state") in {"finished", "timed_out", "cancelled"}


def _android_status_log_tail(stdout: str) -> str:
    _, separator, log_tail = stdout.partition("\n\n")
    return log_tail.strip() if separator else ""


def _android_build_cancel_command(state_dir: str, job_id: str) -> str:
    job_dir = str(PurePosixPath(state_dir) / job_id)
    script = f"""
set -eu
job_id={shlex.quote(job_id)}
job_dir={shlex.quote(job_dir)}
if [ ! -d "$job_dir" ]; then
    echo "unknown android build job: $job_id" >&2
    exit 2
fi
pid=$(cat "$job_dir/pid" 2>/dev/null || true)
expected_start=$(cat "$job_dir/process_start" 2>/dev/null || true)
actual_start=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f20 || true)
if [ -f "$job_dir/returncode" ] || [ -f "$job_dir/timed_out" ]; then
    echo "job already finished: $job_id"
    exit 0
fi
date -Is > "$job_dir/cancel_requested"
if [ -n "$watchdog_pid" ] && [ -n "$watchdog_expected_start" ] && [ "$watchdog_actual_start" = "$watchdog_expected_start" ]; then
    kill "$watchdog_pid" 2>/dev/null || true
fi
if [ -n "$pid" ] && [ -n "$expected_start" ] && [ "$actual_start" = "$expected_start" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM -"$pid" 2>/dev/null || true
    printf 'cancellation requested for %s (process group %s)\n' "$job_id" "$pid"
else
    printf 'job %s is no longer running; marked cancelled\n' "$job_id"
fi
"""
    return remote_command(["sh", "-lc", script])


def _default_screenshot_path(device: DeviceConfig, label: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    return f"{_device_home_path(device)}/Pictures/Screenshots/{label}-{timestamp}.png"


def _screenshot_prepare_command(device: DeviceConfig, remote_path: str) -> str:
    remote_dir = str(PurePosixPath(remote_path).parent)
    home_path = _device_home_path(device)
    script = f"""
set -e
home={shlex.quote(home_path)}
remote_dir={shlex.quote(remote_dir)}
owner=$(stat -Lc %U "$home")
group=$(stat -Lc %G "$home")
if [ "$remote_dir" = "$home/Pictures/Screenshots" ]; then
    if [ ! -d "$home/Pictures" ]; then
        install -d -m 775 -o "$owner" -g "$group" "$home/Pictures"
    fi
    if getent group privileged >/dev/null 2>&1; then
        screenshot_group=privileged
    else
        screenshot_group=$group
    fi
    if [ ! -d "$remote_dir" ]; then
        install -d -m 755 -o "$owner" -g "$screenshot_group" "$remote_dir"
    fi
else
    if [ ! -d "$remote_dir" ]; then
        install -d -m 755 -o "$owner" -g "$group" "$remote_dir"
    fi
fi
""".strip()
    return remote_command(["sh", "-lc", script])


def _run_as_user_command(device: DeviceConfig, inner: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", device.username):
        raise ValueError("device username contains unsupported characters")
    username = shlex.quote(device.username)
    quoted_inner = shlex.quote(inner)
    script = f"""
if command -v runuser >/dev/null 2>&1; then
    runuser -u {username} -- {inner}
else
    su -s /bin/sh {username} -c {quoted_inner}
fi
""".strip()
    return remote_command(["sh", "-lc", script])


def _browser_launch_command(
    device: DeviceConfig,
    url: str,
    stop_stale: bool,
    wait_seconds: int,
) -> str:
    script = f"""
set -u
export XDG_RUNTIME_DIR={shlex.quote(device.user_bus_runtime_dir)}
export DBUS_SESSION_BUS_ADDRESS={shlex.quote(device.user_bus_address)}
if [ {shlex.quote("1" if stop_stale else "0")} = 1 ]; then
    systemctl --user stop booster-browser@sailfish-browser.service >/dev/null 2>&1 || true
    browser_name=sailfish-browser
    for pid in $(pidof "$browser_name" 2>/dev/null || true); do
        kill "$pid" >/dev/null 2>&1 || true
    done
    if command -v ps >/dev/null 2>&1; then
        firejail_name=firejail
        ps -eo pid=,comm=,args= 2>/dev/null |
            awk -v c="$firejail_name" -v b="$browser_name" '$2 == c && index($0, b) {{ print $1 }}' |
            while read -r pid; do
                [ -n "$pid" ] || continue
                kill "$pid" >/dev/null 2>&1 || true
            done
    fi
fi
WAYLAND_DISPLAY=../../display/wayland-0 QT_QPA_PLATFORM=hwcomposer \\
    /usr/bin/invoker --type=browser,silica-qt5 -A -- \\
    /usr/bin/sailfish-browser {shlex.quote(url)} \\
    >/tmp/sailfish-browser-mcp.log 2>&1 &
launcher_pid=$!
echo "launcher_pid=$launcher_pid"
echo "launch_log=/tmp/sailfish-browser-mcp.log"
if [ {wait_seconds} -gt 0 ]; then
    sleep {wait_seconds}
fi
reply=$(dbus-send --session --print-reply \\
    --dest=org.nemomobile.lipstick \\
    / \\
    org.nemomobile.compositor.privateTopmostWindowProcessId 2>/dev/null || true)
topmost_pid=$(printf '%s\\n' "$reply" | awk '$1 ~ /^(int32|uint32|int64|uint64)$/ {{ print $2; exit }}')
if [ -n "$topmost_pid" ]; then
    echo "topmost_pid=$topmost_pid"
    if [ -r "/proc/$topmost_pid/maps" ]; then
        if grep -q 'libxul\\.so' "/proc/$topmost_pid/maps"; then
            echo "libxul=present"
        else
            echo "libxul=absent"
        fi
    fi
else
    echo "topmost_pid="
fi
""".strip()
    return remote_command(["sh", "-lc", script])


def _local_sdk_path(config: Config, args: dict[str, Any]) -> Path | None:
    value = _optional_str(args, "local_sdk")
    if value:
        return Path(value).expanduser().resolve(strict=False)
    if config.paths.local_sdk:
        return config.paths.local_sdk.expanduser().resolve(strict=False)
    return None


def _local_sdk_target(config: Config, args: dict[str, Any], local_sdk: Path) -> str | None:
    explicit_target = _optional_str(args, "target")
    if explicit_target:
        return explicit_target

    device = config.device(_optional_str(args, "device")) if args.get("device") else None
    arch = _optional_str(args, "arch") or (device.architecture if device else "")
    if not arch:
        return None
    release = _optional_str(args, "release") or (device.release if device else "") or "live"
    normalized_release = build_sailfishos.normalize_local_release(release) or "live"
    matching = [
        target
        for target in build_sailfishos.list_local_sdk_targets(local_sdk)
        if target.arch == arch
        and build_sailfishos.local_target_matches_release(target, normalized_release)
    ]
    if matching:
        return matching[0].target
    if normalized_release == "live":
        return arch
    return f"{arch}-{normalized_release}"


def _local_sdk_docker_argv(local_sdk: Path, command: list[str]) -> list[str]:
    return build_sailfishos.local_sdk_command(local_sdk, command)


def _touch_discover_command(include_evdev_trace: bool) -> str:
    evdev_trace = """
if command -v evdev_trace >/dev/null 2>&1; then
    echo "### evdev_trace -i"
    if command -v timeout >/dev/null 2>&1; then
        timeout 5 evdev_trace -i || true
    else
        evdev_trace -i &
        pid=$!
        sleep 5
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    fi
    echo
fi
""".strip()
    script = f"""
set -e
{evdev_trace if include_evdev_trace else ""}
echo "### /proc/bus/input/devices"
cat /proc/bus/input/devices
""".strip()
    return remote_command(["sh", "-lc", script])


def _touch_inject_command(values: dict[str, str | int]) -> str:
    env = " ".join(
        f"{key}={shlex.quote(str(value))}"
        for key, value in sorted(values.items())
    )
    script = f"""
set -e
{env} python3 - <<'PY'
{_touch_inject_python()}
PY
""".strip()
    return remote_command(["sh", "-lc", script])


def _touch_inject_python() -> str:
    return r'''
import os
import re
import struct
import sys
import time

EV_SYN = 0
EV_KEY = 1
EV_ABS = 3
SYN_REPORT = 0
BTN_TOUCH = 0x14a
ABS_X = 0x00
ABS_Y = 0x01
ABS_MT_SLOT = 0x2f
ABS_MT_POSITION_X = 0x35
ABS_MT_POSITION_Y = 0x36
ABS_MT_TRACKING_ID = 0x39

TOUCH_KEYWORDS = (
    "touch",
    "touchscreen",
    "digitizer",
    "fts",
    "ft5x",
    "goodix",
    "synaptics",
    "cyttsp",
    "atmel",
    "elan",
    "himax",
    "novatek",
    "nvt",
    "silead",
    "gt9",
    "spi3",
)


def die(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


def input_blocks():
    try:
        text = open("/proc/bus/input/devices", encoding="utf-8").read()
    except OSError as exc:
        die(f"failed to read /proc/bus/input/devices: {exc}")
    return [block for block in text.split("\n\n") if block.strip()]


def field(block, prefix):
    for line in block.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def event_handler(block):
    match = re.search(r"\bevent\d+\b", field(block, "H: Handlers="))
    return match.group(0) if match else ""


def name(block):
    value = field(block, "N: Name=")
    return value.strip('"')


def score(block):
    lower = block.lower()
    value = 0
    if any(keyword in lower for keyword in TOUCH_KEYWORDS):
        value += 100
    if "b: abs=" in lower:
        value += 20
    if "b: prop=" in lower:
        value += 5
    if "mouse" in lower or "keyboard" in lower or "keypad" in lower:
        value -= 100
    return value


def discover():
    devices = []
    for block in input_blocks():
        event = event_handler(block)
        if not event:
            continue
        devices.append(
            {
                "path": f"/dev/input/{event}",
                "name": name(block),
                "score": score(block),
            }
        )
    devices.sort(key=lambda item: item["score"], reverse=True)
    return devices


def choose_device():
    explicit = os.environ.get("INPUT_DEVICE", "")
    if explicit:
        return explicit
    devices = discover()
    if not devices or devices[0]["score"] <= 0:
        summary = ", ".join(f"{item['path']}:{item['name']}" for item in devices)
        die(f"could not identify touchscreen input device; candidates: {summary}")
    return devices[0]["path"]


def event(fileobj, event_type, code, value):
    fileobj.write(struct.pack("@llHHi", 0, 0, event_type, code, value))


def sync(fileobj):
    event(fileobj, EV_SYN, SYN_REPORT, 0)


def move(fileobj, x, y):
    event(fileobj, EV_ABS, ABS_MT_POSITION_X, x)
    event(fileobj, EV_ABS, ABS_MT_POSITION_Y, y)
    event(fileobj, EV_ABS, ABS_X, x)
    event(fileobj, EV_ABS, ABS_Y, y)


def down(fileobj, x, y):
    event(fileobj, EV_ABS, ABS_MT_SLOT, 0)
    event(fileobj, EV_ABS, ABS_MT_TRACKING_ID, int(time.time() * 1000) & 0x7fffffff)
    move(fileobj, x, y)
    event(fileobj, EV_KEY, BTN_TOUCH, 1)
    sync(fileobj)


def up(fileobj):
    event(fileobj, EV_ABS, ABS_MT_SLOT, 0)
    event(fileobj, EV_ABS, ABS_MT_TRACKING_ID, -1)
    event(fileobj, EV_KEY, BTN_TOUCH, 0)
    sync(fileobj)


def integer(name):
    try:
        return int(os.environ[name])
    except KeyError:
        die(f"missing {name}")
    except ValueError:
        die(f"{name} must be an integer")


action = os.environ.get("ACTION", "")
device = choose_device()
print(f"input_device={device}")
with open(device, "wb", buffering=0) as fileobj:
    if action == "tap":
        down(fileobj, integer("X"), integer("Y"))
        time.sleep(integer("HOLD_MS") / 1000)
        up(fileobj)
    elif action == "swipe":
        start_x = integer("START_X")
        start_y = integer("START_Y")
        end_x = integer("END_X")
        end_y = integer("END_Y")
        steps = integer("STEPS")
        duration = integer("DURATION_MS") / 1000
        down(fileobj, start_x, start_y)
        for step in range(1, steps + 1):
            fraction = step / steps
            x = round(start_x + ((end_x - start_x) * fraction))
            y = round(start_y + ((end_y - start_y) * fraction))
            move(fileobj, x, y)
            sync(fileobj)
            time.sleep(duration / steps)
        up(fileobj)
    else:
        die(f"unsupported ACTION {action!r}")
print(f"{action}=ok")
'''.strip()


def _device_home_path(device: DeviceConfig) -> str:
    return f"/home/{device.username}"


def command_result(
    title: str,
    result: CommandResult,
    structured: dict[str, Any] | None = None,
    *,
    verbose: bool = False,
) -> dict[str, Any]:
    data = result.public_dict() if verbose else result.summary_dict()
    if structured:
        data.update(structured)
    return {
        "content": [
            {
                "type": "text",
                "text": _command_text(
                    title,
                    result,
                    stdout_limit=12000 if verbose else 4000,
                    stderr_limit=8000 if verbose else 2000,
                ),
            }
        ],
        "structuredContent": data,
        "isError": not result.ok,
    }


def combined_result(title: str, steps: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    text_parts: list[str] = []
    structured_steps: dict[str, Any] = {}
    is_error = False
    for name, result in steps:
        content = result.get("content") or []
        step_text = content[0].get("text", "") if content else ""
        text_parts.append(f"{name}:\n{step_text}".rstrip())
        structured_steps[name] = result.get("structuredContent", {})
        is_error = is_error or bool(result.get("isError", False))
    return {
        "content": [{"type": "text", "text": "\n\n".join(text_parts)}],
        "structuredContent": {
            "title": title,
            "step_order": [name for name, _ in steps],
            "steps": structured_steps,
        },
        "isError": is_error,
    }


def ok_text(text: str, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured or {},
        "isError": False,
    }


def tool_error(message: str, structured: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": structured or {"error": message},
        "isError": True,
    }


def _command_text(
    title: str,
    result: CommandResult,
    *,
    stdout_limit: int = 4000,
    stderr_limit: int = 2000,
) -> str:
    stdout, _ = truncate(result.stdout, stdout_limit)
    stderr, _ = truncate(result.stderr, stderr_limit)
    parts = [f"{title}: exit {result.returncode}"]
    if stdout:
        parts += ["", stdout.rstrip()]
    if stderr:
        parts += ["", "stderr:", stderr.rstrip()]
    return "\n".join(parts)


def _device(config: Config, args: dict[str, Any]) -> DeviceConfig:
    return config.device(_optional_str(args, "device"))


def _obs_server_selection(config: Config, args: dict[str, Any]) -> tuple[str | None, str]:
    server = _optional_str(args, "server")
    api_alias = _optional_str(args, "api_alias")
    if server and api_alias:
        raise ValueError("server and api_alias cannot be combined")
    if server:
        try:
            return server, config.paths.obs_servers[server]
        except KeyError as exc:
            choices = ", ".join(config.paths.obs_servers)
            if choices:
                message = f"server must be one of: {choices}"
            else:
                message = "no named OBS servers are configured in paths.obs_servers"
            raise ValueError(message) from exc

    selected_alias = api_alias or config.paths.osc_api_alias
    selected_server = next(
        (
            name
            for name, alias in config.paths.obs_servers.items()
            if alias == selected_alias
        ),
        None,
    )
    return selected_server, selected_alias


def _str_arg(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _optional_str(args: dict[str, Any], name: str) -> str | None:
    value = args.get(name)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _int_arg(
    args: dict[str, Any],
    name: str,
    default: int | None = None,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    value = args.get(name, default)
    if not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")
    return value


def _bool_arg(args: dict[str, Any], name: str, default: bool = False) -> bool:
    value = args.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _enum_arg(
    args: dict[str, Any],
    name: str,
    values: list[str],
    default: str | None = None,
) -> str:
    value = args.get(name, default)
    if not isinstance(value, str) or value not in values:
        raise ValueError(f"{name} must be one of: {', '.join(values)}")
    return value


def _string_list_arg(args: dict[str, Any], name: str) -> list[str]:
    value = args.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a list of strings")
    return value


def _command_list_arg(args: dict[str, Any], name: str) -> list[str]:
    value = args.get(name)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError(f"{name} must be a non-empty list of strings")
    return value


def _service_unit_arg(args: dict[str, Any], name: str) -> str:
    unit = _str_arg(args, name)
    if not re.fullmatch(r"[A-Za-z0-9@_.:\-]+", unit):
        raise ValueError(f"{name} contains unsupported characters")
    return unit


def _safe_input_path(config: Config, value: str, *, allow_tmp: bool) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config.paths.git_root / path
    path = path.resolve(strict=False)
    roots = _host_path_roots(config)
    if allow_tmp:
        roots.append(Path("/tmp").resolve(strict=False))
    if not _is_relative_to_any(path, roots):
        raise ValueError(f"path is outside allowed roots: {path}")
    return path


def _safe_output_path(config: Config, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = config.paths.git_root / path
    path = path.resolve(strict=False)
    roots = _host_path_roots(config) + [Path("/tmp").resolve(strict=False)]
    if not _is_relative_to_any(path, roots):
        raise ValueError(f"output path is outside allowed roots: {path}")
    return path


def _safe_local_sdk_path(config: Config, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise ValueError("local_sdk must be an absolute path")
    path = path.resolve(strict=False)
    srv_mer = Path("/srv/mer").resolve(strict=False)
    configured = (
        config.paths.local_sdk.expanduser().resolve(strict=False)
        if config.paths.local_sdk
        else None
    )
    if not _is_relative_to_any(path, [srv_mer]) and path != configured:
        raise ValueError("local_sdk must be under /srv/mer or match the configured SDK path")
    return path


def _host_path_roots(config: Config) -> list[Path]:
    roots: list[Path] = []
    for root in (config.paths.git_root, config.paths.obs_root):
        resolved = root.resolve(strict=False)
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _is_relative_to_any(path: Path, roots: list[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            pass
    return False


def _parse_dbus_integer(text: str) -> int | None:
    match = re.search(r"\b(?:int32|uint32|int64|uint64)\s+(-?\d+)", text)
    return int(match.group(1)) if match else None


def _parse_spec(path: Path) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "Name": "",
        "Version": "",
        "Release": "",
        "Summary": "",
        "License": "",
        "URL": "",
        "BuildRequires": [],
        "Requires": [],
    }
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for field in ["Name", "Version", "Release", "Summary", "License", "URL"]:
            prefix = field + ":"
            if line.startswith(prefix) and not fields[field]:
                fields[field] = line[len(prefix) :].strip()
        if line.startswith("BuildRequires:"):
            fields["BuildRequires"].append(line.split(":", 1)[1].strip())
        if line.startswith("Requires:"):
            fields["Requires"].append(line.split(":", 1)[1].strip())
    return fields


def _read_only_annotations(title: str) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    }


def _mutating_annotations(title: str, *, destructive: bool = False) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": False,
        "destructiveHint": destructive,
        "idempotentHint": False,
        "openWorldHint": True,
    }


def _object_schema(properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties,
        "required": required or [],
        "additionalProperties": False,
    }


def _device_prop() -> dict[str, Any]:
    return {
        "type": "string",
        "description": (
            "Configured device alias or ssh target. When the user says the device "
            "is attached over USB, use 'usb' for the default device or "
            "'usb:<name>' when the user supplies a device name. The USB connection "
            "trusts that name for device metadata and does not resolve it through DNS."
        ),
    }


def _timeout_prop(default: int) -> dict[str, Any]:
    return {
        "type": "integer",
        "minimum": 1,
        "default": default,
        "description": "Command timeout in seconds.",
    }


def _verbose_prop() -> dict[str, Any]:
    return {
        "type": "boolean",
        "default": False,
        "description": "Include full command, stdout, and stderr details for diagnostics.",
    }


def _spec_devices() -> dict[str, Any]:
    return {
        "name": "sailfish_devices",
        "title": "List Sailfish Devices",
        "description": "List configured Sailfish OS device aliases and SSH targets.",
        "inputSchema": _object_schema({}),
        "annotations": _read_only_annotations("List Sailfish Devices"),
    }


def _spec_device_setup() -> dict[str, Any]:
    return {
        "name": "sailfish_device_setup",
        "title": "Check or Set Up Device Prerequisites",
        "description": (
            "Check command availability and session configuration over SSH. By default this only reads device state. "
            "Explicit install_missing=true installs missing python3-base or mce-tools from existing repositories "
            "in a detached job; use sailfish_build_status/cancel. Missing base OS tools need manual repair. "
            "Set companion=check to inspect the optional device companion or deploy to install/update and start it. "
            "Before requesting first-install permission, warn: development/test devices only; do not install on personal or primary phones "
            "containing real accounts or sensitive data. Captures may expose private application/account data to the host MCP client and model context. "
            "ALWAYS ask permission before its first installation on each device; only then set confirm_companion_install=true. "
            "Updates to recognized installations need no new permission. Deployment resets capture history."
        ),
        "inputSchema": _object_schema({
            "device": _device_prop(),
            "features": {"type": "array", "minItems": 1,
                         "items": {"type": "string", "enum": list(DEVICE_FEATURES)}},
            "install_missing": {"type": "boolean", "default": False},
            "companion": {"type": "string", "enum": ["none", "check", "deploy"], "default": "none"},
            "confirm_companion_install": {"type": "boolean", "default": False,
                "description": "True only after presenting the personal-device/data-exposure warning and receiving explicit permission for first companion installation on this device. Not needed for updates."},
            "wait": {"type": "boolean", "default": False,
                     "description": "Wait for installation; use the default detached job for long work."},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 1200, "default": 600},
        }),
        "annotations": _mutating_annotations("Check or Set Up Device Prerequisites"),
    }


def _spec_device_journal() -> dict[str, Any]:
    return {
        "name": "sailfish_device_journal",
        "title": "Read Device Journal",
        "description": "Read recent journalctl output from a Sailfish OS device.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "unit": {"type": "string"},
                "since": {"type": "string"},
                "grep": {"type": "string"},
                "lines": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 200},
                "timeout": _timeout_prop(30),
            }
        ),
        "annotations": _read_only_annotations("Read Device Journal"),
    }


def _spec_device_topmost_pid() -> dict[str, Any]:
    return {
        "name": "sailfish_device_topmost_pid",
        "title": "Topmost Window PID",
        "description": "Query Lipstick for the current topmost window process id.",
        "inputSchema": _object_schema({"device": _device_prop(), "timeout": _timeout_prop(20)}),
        "annotations": _read_only_annotations("Topmost Window PID"),
    }


def _spec_device_proc_maps() -> dict[str, Any]:
    return {
        "name": "sailfish_device_proc_maps",
        "title": "Read Process Maps",
        "description": "Read or filter /proc/<pid>/maps on a Sailfish OS device.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "pid": {"type": "integer", "minimum": 1},
                "contains": {"type": "string"},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 200},
                "timeout": _timeout_prop(20),
            },
            ["pid"],
        ),
        "annotations": _read_only_annotations("Read Process Maps"),
    }


def _spec_device_lipstick_screenshot() -> dict[str, Any]:
    return {
        "name": "sailfish_device_lipstick_screenshot",
        "title": "Lipstick Screenshot",
        "description": "Ask Lipstick to save a screenshot on the device, optionally pulling it locally.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "remote_path": {
                    "type": "string",
                    "default": "/home/defaultuser/Pictures/Screenshots/lipstick-<timestamp>.png",
                    "description": "Lipstick accepts screenshot paths under the user home directory.",
                },
                "local_path": {"type": "string"},
                "privileged": {"type": "boolean", "default": True},
                "timeout": _timeout_prop(30),
            }
        ),
        "annotations": _mutating_annotations("Lipstick Screenshot"),
    }


def _spec_device_touch() -> dict[str, Any]:
    return {
        "name": "sailfish_device_touch",
        "title": "Device Touch Input",
        "description": "Discover the touchscreen input device or inject tap/swipe events over SSH.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "action": {
                    "type": "string",
                    "enum": ["discover", "tap", "swipe"],
                    "description": "discover lists input devices; tap and swipe inject Linux input events.",
                },
                "include_evdev_trace": {
                    "type": "boolean",
                    "default": False,
                    "description": "Also run evdev_trace -i during discovery. Disabled by default because it may block on some devices.",
                },
                "input_device": {
                    "type": "string",
                    "description": "Optional explicit device path, for example /dev/input/event5.",
                },
                "x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "hold_ms": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 80},
                "start_x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "start_y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "end_x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "end_y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "duration_ms": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 300},
                "steps": {"type": "integer", "minimum": 1, "maximum": 200, "default": 12},
                "timeout": _timeout_prop(10),
            },
            ["action"],
        ),
        "annotations": _mutating_annotations("Device Touch Input"),
    }


def _spec_device_touch_workflow() -> dict[str, Any]:
    return {
        "name": "sailfish_device_touch_workflow",
        "title": "Screenshot And Touch",
        "description": "Capture a Lipstick screenshot, optionally list touch inputs, then inject a tap or swipe.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "action": {"type": "string", "enum": ["tap", "swipe"]},
                "input_device": {
                    "type": "string",
                    "description": "Optional explicit device path, for example /dev/input/event5.",
                },
                "x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "hold_ms": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 80},
                "start_x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "start_y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "end_x": {"type": "integer", "minimum": 0, "maximum": 10000},
                "end_y": {"type": "integer", "minimum": 0, "maximum": 10000},
                "duration_ms": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 300},
                "steps": {"type": "integer", "minimum": 1, "maximum": 200, "default": 12},
                "screenshot_before": {"type": "boolean", "default": True},
                "screenshot_after": {"type": "boolean", "default": False},
                "discover_input": {"type": "boolean", "default": True},
                "include_evdev_trace": {"type": "boolean", "default": False},
                "privileged": {"type": "boolean", "default": True},
                "local_path": {
                    "type": "string",
                    "description": "Optional local path for the before screenshot.",
                },
                "before_local_path": {"type": "string"},
                "after_local_path": {"type": "string"},
                "before_remote_path": {"type": "string"},
                "after_remote_path": {"type": "string"},
                "timeout": _timeout_prop(30),
            },
            ["action"],
        ),
        "annotations": _mutating_annotations("Screenshot And Touch"),
    }


def _spec_device_user_bus_call() -> dict[str, Any]:
    return {
        "name": "sailfish_device_user_bus_call",
        "title": "User Bus Call",
        "description": "Run a typed dbus-send method call on the defaultuser session bus.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "destination": {"type": "string"},
                "path": {"type": "string"},
                "interface": {"type": "string"},
                "member": {"type": "string"},
                "arguments": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Raw dbus-send argument strings, for example string:/tmp/file.",
                },
                "timeout": _timeout_prop(30),
            },
            ["destination", "path", "interface", "member"],
        ),
        "annotations": _mutating_annotations("User Bus Call"),
    }


def _spec_device_user_session_command() -> dict[str, Any]:
    return {
        "name": "sailfish_device_user_session_command",
        "title": "User Session Command",
        "description": (
            f"Run a short command, limited to {MAX_MCP_WAIT_SECONDS} seconds, with the "
            "configured Sailfish "
            "user-session D-Bus environment. Use sailfish_device_command_start for "
            "anything that may run longer."
        ),
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Command argv to run; shell parsing is not applied.",
                },
                "run_as_user": {
                    "type": "boolean",
                    "default": False,
                    "description": "Run through runuser/su as the configured device username.",
                },
                "verbose": _verbose_prop(),
                "timeout": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_MCP_WAIT_SECONDS,
                    "default": MAX_MCP_WAIT_SECONDS,
                    "description": (
                        "Command timeout in seconds; long commands must use an async job."
                    ),
                },
            },
            ["command"],
        ),
        "annotations": _mutating_annotations("User Session Command"),
    }


def _device_command_common_properties() -> dict[str, Any]:
    return {
        "device": _device_prop(),
        "command": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 1,
            "description": "Command argv to run; shell parsing is not applied.",
        },
        "run_as_user": {
            "type": "boolean",
            "default": False,
            "description": "Run through runuser/su as the configured device username.",
        },
    }


def _spec_device_command_start() -> dict[str, Any]:
    return {
        "name": "sailfish_device_command_start",
        "title": "Start Device Command Job",
        "description": (
            "Prefer a device-companion job, with detached SSH fallback when unavailable, using the configured Sailfish user-session "
            "environment and immediately return a job id. Use this for GDB, tracing, "
            f"and any device command that may exceed {MAX_MCP_WAIT_SECONDS} seconds."
        ),
        "inputSchema": _object_schema(
            {
                **_device_command_common_properties(),
                "timeout": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86400,
                    "default": 3600,
                    "description": "Detached job lifetime in seconds.",
                },
            },
            ["command"],
        ),
        "annotations": _mutating_annotations("Start Device Command Job"),
    }


def _spec_device_command_status() -> dict[str, Any]:
    return {
        "name": "sailfish_device_command_status",
        "title": "Device Command Job Status",
        "description": (
            "List detached device command jobs or read one job's status. A bounded "
            "failure excerpt is included automatically; running logs are omitted by default."
        ),
        "inputSchema": _object_schema(
            {
                "job_id": {
                    "type": "string",
                    "description": (
                        "Job id returned by sailfish_device_command_start. "
                        "Omit to list recent jobs."
                    ),
                },
                "lines": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1000,
                    "default": 0,
                    "description": (
                        "Trailing log lines to include. Keep zero while the job is running; "
                        "failed jobs include a bounded failure excerpt."
                    ),
                },
                "log_offset": {"type": "integer", "minimum": 0, "description": "Read a bounded log page from this byte offset."},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 12000, "default": 6000},
                "after_revision": {"type": "string", "description": "Last revision; unchanged results omit repeated details."},
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_MCP_WAIT_SECONDS,
                    "default": 0,
                    "description": (
                        f"Wait at most {MAX_MCP_WAIT_SECONDS} seconds for a terminal state."
                    ),
                },
                "verbose": _verbose_prop(),
            }
        ),
        "annotations": _read_only_annotations("Device Command Job Status"),
    }


def _spec_device_command_cancel() -> dict[str, Any]:
    return {
        "name": "sailfish_device_command_cancel",
        "title": "Cancel Device Command Job",
        "description": "Request cancellation of a detached device command and its process group.",
        "inputSchema": _object_schema({"job_id": {"type": "string"}}, ["job_id"]),
        "annotations": _mutating_annotations("Cancel Device Command Job"),
    }


def _spec_device_install_rpm() -> dict[str, Any]:
    return {
        "name": "sailfish_device_install_rpm",
        "title": "Install Device RPM",
        "description": "Start a detached RPM copy/install transaction; use sailfish_build_status/cancel.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "rpm_path": {
                    "type": "string",
                    "description": "Single local RPM path. Use rpm_paths for dependency sets.",
                },
                "rpm_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Local RPM paths to copy and install in one transaction.",
                },
                "remote_path": {
                    "type": "string",
                    "description": "Remote file path override for a single rpm_path.",
                },
                "remote_dir": {
                    "type": "string",
                    "description": "Remote directory for copied RPMs. Created when missing.",
                },
                "installer": {"type": "string", "enum": ["pkcon", "rpm"], "default": "pkcon"},
                "wait": {"type": "boolean", "default": False, "description": "Legacy synchronous execution; default returns a job for sailfish_build_status/cancel."},
                "timeout": _timeout_prop(180),
            }
        ),
        "annotations": _mutating_annotations("Install Device RPM"),
    }


def _spec_device_restart_service() -> dict[str, Any]:
    return {
        "name": "sailfish_device_restart_service",
        "title": "Manage Device Service",
        "description": "Run systemctl start/stop/restart/status for a system or user service.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "unit": {"type": "string"},
                "action": {
                    "type": "string",
                    "enum": ["restart", "start", "stop", "status"],
                    "default": "restart",
                },
                "mode": {"type": "string", "enum": ["system", "user"], "default": "system"},
                "timeout": _timeout_prop(60),
            },
            ["unit"],
        ),
        "annotations": _mutating_annotations("Manage Device Service"),
    }


def _spec_device_app_launch() -> dict[str, Any]:
    return {
        "name": "sailfish_device_app_launch",
        "title": "Launch a Sailfish application",
        "description": (
            "Launch an installed .desktop entry using gio as the configured session "
            "user from their home. Detaches all streams and returns a launch receipt "
            "and remote log/status paths. Does not stop apps or boosters. Submission "
            "is not proof of foreground activation or rendering; verify separately."
        ),
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "desktop_file": {
                    "type": "string",
                    "description": "Installed desktop basename (for example sailfish-browser.desktop) or absolute device path ending in .desktop.",
                },
                "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 5, "default": 1},
                "timeout": {"type": "integer", "minimum": 1, "maximum": 15, "default": 15},
            },
            ["desktop_file"],
        ),
        "annotations": _mutating_annotations("Launch a Sailfish application"),
    }


def _spec_device_browser_launch() -> dict[str, Any]:
    return {
        "name": "sailfish_device_browser_launch",
        "title": "Launch Sailfish Browser",
        "description": "Stop stale browser state, launch Sailfish Browser with display/session env, and report topmost PID details.",
        "inputSchema": _object_schema(
            {
                "device": _device_prop(),
                "url": {"type": "string"},
                "stop_stale": {"type": "boolean", "default": True},
                "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 60, "default": 3},
                "timeout": _timeout_prop(60),
            },
            ["url"],
        ),
        "annotations": _mutating_annotations("Launch Sailfish Browser"),
    }


def _spec_build_rpm() -> dict[str, Any]:
    return {
        "name": "sailfish_build_rpm",
        "title": "Build Sailfish RPM",
        "description": "Start an asynchronous RPM build. Ordinary local builds share mb2 snapshots; custom inputs or an explicit key use an isolated original target. paths.local_sdk defaults to the live installed SDK, with third-party coderus Docker-image fallback only for explicit named releases.",
        "inputSchema": _object_schema(
            {
                "project_path": {"type": "string"},
                "spec_path": {
                    "type": "string",
                    "description": "RPM spec relative to the resolved project root; required when multiple specs exist.",
                },
                "reset_snapshot": {
                    "type": "boolean", "default": False,
                    "description": "Deliberately reset the managed project snapshot and reapply its dependency inputs. Never resets a base target.",
                },
                "resume_snapshot": {
                    "type": "boolean", "default": False,
                    "description": "Explicitly reapply an existing snapshot's identical recorded recipe without resetting. Unknown or different recipes are rejected.",
                },
                "device": {
                    "type": "string",
                    "description": "Optional configured device to supply default release and architecture.",
                },
                "release": {"type": "string"},
                "backend": {
                    "type": "string",
                    "enum": ["auto", "docker", "local"],
                    "default": "auto",
                },
                "local_sdk": {
                    "type": "string",
                    "description": "Installed sdk-chroot path under /srv/mer; defaults to paths.local_sdk.",
                },
                "snapshot_key": {
                    "type": "string",
                    "description": "Stable logical SDK snapshot key (for example one shared by all worktrees of an ESR generation). Omit to share ordinary builds; custom inputs infer an ESR-aware key. Supply a project key when repository policy requires isolation.",
                },
                "snapshot_repository": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional [ALIAS=]URL repository to prepare in the project snapshot; may contain multiple values.",
                },
                "snapshot_package": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional package to prepare in the project snapshot; may be repeated in the request.",
                },
                "arch": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ]
                },
                "target": {
                    "oneOf": [
                        {"type": "string"},
                        {"type": "array", "items": {"type": "string"}},
                    ],
                    "description": "Registered non-snapshot local SDK base target; the build runs in a managed project snapshot.",
                },
                "artifacts_dir": {"type": "string"},
                "all_arches": {"type": "boolean", "default": False},
                "clean": {"type": "boolean", "default": False},
                "debug": {"type": "boolean", "default": False},
                "permission_fallback": {
                    "type": "string",
                    "enum": ["error", "chmod"],
                    "default": "error",
                },
                "no_pull": {"type": "boolean", "default": False},
                "pull_policy": {
                    "type": "string",
                    "enum": ["always", "missing", "never"],
                    "default": "always",
                },
                "no_vcs_apply": {"type": "boolean", "description": "Omit for backend default; false explicitly enables VCS application."},
                "allow_untrusted_rpms": {"type": "boolean", "default": False},
                "local_rpms_dir": {"type": "array", "items": {"type": "string"}},
                "wait": {
                    "type": "boolean",
                    "default": False,
                    "description": "Wait for the build and return the old synchronous command result.",
                },
                "timeout": _timeout_prop(3600),
            },
            ["project_path"],
        ),
        "annotations": _mutating_annotations("Build Sailfish RPM"),
    }


def _spec_build_preflight() -> dict[str, Any]:
    properties = dict(_spec_build_rpm()["inputSchema"]["properties"])
    properties.pop("wait", None)
    properties["timeout"] = _timeout_prop(120)
    return {
        "name": "sailfish_build_preflight",
        "title": "Preflight Sailfish Build",
        "description": "Validate and return a structured Sailfish RPM build plan without mutating the project.",
        "inputSchema": _object_schema(properties, ["project_path"]),
        "annotations": _read_only_annotations("Preflight Sailfish Build"),
    }


def _spec_build_status() -> dict[str, Any]:
    return {
        "name": "sailfish_build_status",
        "title": "Build Job Status",
        "description": "Read status and recent log output for asynchronous Sailfish RPM build jobs.",
        "inputSchema": _object_schema(
            {
                "job_id": {
                    "type": "string",
                    "description": "Build job id returned by sailfish_build_rpm. Omit to list recent jobs.",
                },
                "lines": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1000,
                    "default": 0,
                    "description": (
                        "Trailing log lines to include. The default returns no running log; "
                        "failed jobs include a bounded failure excerpt."
                    ),
                },
                "log_offset": {"type": "integer", "minimum": 0, "description": "Read a bounded log page from this byte offset."},
                "max_bytes": {"type": "integer", "minimum": 1, "maximum": 12000, "default": 6000},
                "after_revision": {"type": "string", "description": "Last revision; unchanged results omit repeated details."},
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_MCP_WAIT_SECONDS,
                    "default": 0,
                    "description": (
                        f"Wait at most {MAX_MCP_WAIT_SECONDS} seconds for job completion."
                    ),
                },
                "verbose": _verbose_prop(),
            }
        ),
        "annotations": _read_only_annotations("Build Job Status"),
    }


def _spec_build_cancel() -> dict[str, Any]:
    return {
        "name": "sailfish_build_cancel",
        "title": "Cancel Sailfish Build",
        "description": "Request cancellation of a local asynchronous Sailfish RPM build job.",
        "inputSchema": _object_schema({"job_id": {"type": "string"}}, ["job_id"]),
        "annotations": _mutating_annotations("Cancel Sailfish Build"),
    }


def _spec_android_build_hosts() -> dict[str, Any]:
    return {
        "name": "sailfish_android_build_hosts",
        "title": "Android Build Hosts",
        "description": "List configured remote Android/AppSupport build hosts.",
        "inputSchema": _object_schema({}),
        "annotations": _read_only_annotations("Android Build Hosts"),
    }


def _spec_android_build() -> dict[str, Any]:
    return {
        "name": "sailfish_android_build",
        "title": "Start Android Build",
        "description": (
            "Start a remote Android/AppSupport build under nohup on the configured "
            "build host; project_dir must be configured for the host or supplied."
        ),
        "inputSchema": _object_schema(
            {
                "host": {
                    "type": "string",
                    "description": "Configured build host alias or ssh target.",
                },
                "project_dir": {
                    "type": "string",
                    "description": "Remote Android tree. Defaults to the host config.",
                },
                "state_dir": {
                    "type": "string",
                    "description": "Remote directory where job state and logs are stored.",
                },
                "shell_command": {
                    "type": "string",
                    "description": (
                        "Build command run from project_dir, for example "
                        "'source build/envsetup.sh && lunch ... && m ...'."
                    ),
                },
                "job_id": {
                    "type": "string",
                    "description": "Optional stable job id; autogenerated when omitted.",
                },
                "shell": {
                    "type": "string",
                    "enum": ["bash", "sh"],
                    "default": "bash",
                },
                "build_timeout": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 86400,
                    "default": 0,
                    "description": "Remote build lifetime in seconds; zero disables the build timeout.",
                },
                "timeout": _timeout_prop(60),
            },
            ["shell_command"],
        ),
        "annotations": _mutating_annotations("Start Android Build"),
    }


def _spec_android_build_status() -> dict[str, Any]:
    return {
        "name": "sailfish_android_build_status",
        "title": "Android Build Status",
        "description": (
            "List remote Android/AppSupport build jobs or read one job's status and "
            "recent log output."
        ),
        "inputSchema": _object_schema(
            {
                "host": {
                    "type": "string",
                    "description": "Configured build host alias or ssh target.",
                },
                "job_id": {
                    "type": "string",
                    "description": "Job id returned by sailfish_android_build. Omit to list jobs.",
                },
                "state_dir": {
                    "type": "string",
                    "description": "Remote directory where job state and logs are stored.",
                },
                "lines": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 1000,
                    "default": 0,
                    "description": (
                        "Trailing log lines to include. The default returns no running log; "
                        "failed jobs include a bounded failure excerpt."
                    ),
                },
                "after_revision": {"type": "string", "description": "Last revision; unchanged results omit repeated details."},
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_MCP_WAIT_SECONDS,
                    "default": 0,
                    "description": (
                        "Mechanically wait at most "
                        f"{MAX_MCP_WAIT_SECONDS} seconds for a terminal state."
                    ),
                },
                "poll_interval": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 5,
                    "description": "Seconds between status checks while waiting.",
                },
                "verbose": _verbose_prop(),
                "timeout": _timeout_prop(30),
            }
        ),
        "annotations": _read_only_annotations("Android Build Status"),
    }


def _spec_android_build_cancel() -> dict[str, Any]:
    return {
        "name": "sailfish_android_build_cancel",
        "title": "Cancel Android Build",
        "description": "Cancel a remote Android/AppSupport build after verifying its process identity.",
        "inputSchema": _object_schema(
            {
                "host": {
                    "type": "string",
                    "description": "Configured build host alias or ssh target.",
                },
                "job_id": {"type": "string"},
                "state_dir": {"type": "string"},
                "timeout": _timeout_prop(30),
            },
            ["job_id"],
        ),
        "annotations": _mutating_annotations("Cancel Android Build"),
    }


def _spec_sdk_refresh_metadata() -> dict[str, Any]:
    return {
        "name": "sailfish_sdk_refresh_metadata",
        "title": "Refresh SDK Metadata",
        "description": "Start a detached SDK metadata refresh; use sailfish_build_status/cancel.",
        "inputSchema": _object_schema(
            {
                "device": {
                    "type": "string",
                    "description": "Optional configured device to supply default release and architecture.",
                },
                "local_sdk": {
                    "type": "string",
                    "description": "Override paths.local_sdk for this call.",
                },
                "target": {
                    "type": "string",
                    "description": "Exact SDK target to refresh: aarch64 means the parent, aarch64.default or aarch64-project means that specific snapshot. No implicit suffix is added.",
                },
                "release": {"type": "string"},
                "arch": {"type": "string"},
                "force": {
                    "type": "boolean",
                    "default": False,
                    "description": "Append zypper ref -f.",
                },
                "wait": {"type": "boolean", "default": False, "description": "Legacy synchronous execution; default returns a job for sailfish_build_status/cancel."},
                "timeout": _timeout_prop(600),
            }
        ),
        "annotations": _mutating_annotations("Refresh SDK Metadata"),
    }


def _spec_obs_results() -> dict[str, Any]:
    return {
        "name": "sailfish_obs_results",
        "title": "OBS Results",
        "description": (
            "Read OBS results. Use wait_seconds for bounded mechanical monitoring "
            "instead of repeated model-driven status calls."
        ),
        "inputSchema": _object_schema(
            {
                "project": {"type": "string"},
                "package": {"type": "string"},
                "server": {
                    "type": "string",
                    "description": "Named OBS server configured in paths.obs_servers.",
                },
                "api_alias": {
                    "type": "string",
                    "description": "Advanced raw osc -A alias or API URL; overrides paths.osc_api_alias and cannot be combined with server.",
                },
                "wait_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": MAX_MCP_WAIT_SECONDS,
                    "default": 0,
                    "description": (
                        "Mechanically wait at most "
                        f"{MAX_MCP_WAIT_SECONDS} seconds while results remain pending."
                    ),
                },
                "poll_interval": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 5,
                    "description": "Seconds between OBS checks while waiting.",
                },
                "verbose": _verbose_prop(),
                "timeout": _timeout_prop(60),
            },
            ["project"],
        ),
        "annotations": _read_only_annotations("OBS Results"),
    }


def _spec_obs_buildlog() -> dict[str, Any]:
    return {
        "name": "sailfish_obs_buildlog",
        "title": "OBS Build Log",
        "description": "Fetch a build log from a configured OBS server or explicit API alias; defaults to the API nostream form.",
        "inputSchema": _object_schema(
            {
                "project": {"type": "string"},
                "package": {"type": "string"},
                "repository": {"type": "string"},
                "arch": {"type": "string"},
                "server": {
                    "type": "string",
                    "description": "Named OBS server configured in paths.obs_servers.",
                },
                "api_alias": {
                    "type": "string",
                    "description": "Advanced raw osc -A alias or API URL; overrides paths.osc_api_alias and cannot be combined with server.",
                },
                "nostream": {"type": "boolean", "default": True},
                "lines": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5000,
                    "default": 120,
                    "description": (
                        "Trailing log lines to return. Use zero with verbose=true "
                        "for the legacy full-output diagnostic response."
                    ),
                },
                "verbose": _verbose_prop(),
                "timeout": _timeout_prop(90),
            },
            ["project", "package", "repository", "arch"],
        ),
        "annotations": _read_only_annotations("OBS Build Log"),
    }


def _spec_repo_status() -> dict[str, Any]:
    return {
        "name": "sailfish_repo_status",
        "title": "Repo Status",
        "description": "Run git status --short --branch under the configured git root.",
        "inputSchema": _object_schema({"path": {"type": "string"}, "timeout": _timeout_prop(30)}),
        "annotations": _read_only_annotations("Repo Status"),
    }


def _spec_repo_find() -> dict[str, Any]:
    return {
        "name": "sailfish_repo_find",
        "title": "Repo Find",
        "description": "Search a repo or subtree under the configured git root.",
        "inputSchema": _object_schema(
            {
                "path": {"type": "string"},
                "query": {"type": "string"},
                "fixed_strings": {"type": "boolean", "default": True},
                "max_count": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                "timeout": _timeout_prop(30),
            },
            ["query"],
        ),
        "annotations": _read_only_annotations("Repo Find"),
    }


def _spec_spec_summary() -> dict[str, Any]:
    return {
        "name": "sailfish_spec_summary",
        "title": "RPM Spec Summary",
        "description": "Parse high-level metadata from a Sailfish RPM spec file.",
        "inputSchema": _object_schema(
            {"repo_path": {"type": "string"}, "spec_path": {"type": "string"}}
        ),
        "annotations": _read_only_annotations("RPM Spec Summary"),
    }


def _spec_qml_find_translations() -> dict[str, Any]:
    return {
        "name": "sailfish_qml_find_translations",
        "title": "Find QML Translations",
        "description": "Find qsTrId and translator comments in QML files.",
        "inputSchema": _object_schema({"path": {"type": "string"}, "timeout": _timeout_prop(30)}),
        "annotations": _read_only_annotations("Find QML Translations"),
    }


def _spec_qml_check_translator_ternaries() -> dict[str, Any]:
    return {
        "name": "sailfish_qml_check_translator_ternaries",
        "title": "Check QML Ternary Translations",
        "description": "Flag QML ternary qsTrId expressions that need branch-local comments.",
        "inputSchema": _object_schema({"path": {"type": "string"}}),
        "annotations": _read_only_annotations("Check QML Ternary Translations"),
    }


def _spec_obs_watch() -> dict[str, Any]:
    return {"name": "sailfish_obs_watch", "description": "Watch OBS until completion in a detached local job; use sailfish_build_status/cancel or the jobs CLI waiter.",
            "inputSchema": _object_schema({
                "project": {"type": "string"}, "package": {"type": "string"},
                "server": {"type": "string", "description": "Named OBS server configured in paths.obs_servers."},
                "api_alias": {"type": "string"}, "timeout": _timeout_prop(21600)}, ["project"]),
            "annotations": _mutating_annotations("Watch OBS builds")}
