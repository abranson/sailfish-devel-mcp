from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import shlex
import subprocess
from typing import Any, Iterable, Sequence

from .config import DeviceConfig


IGNORED_HOST_KEY_OPTIONS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "GlobalKnownHostsFile=/dev/null",
    "-o",
    "CheckHostIP=no",
    "-o",
    "VerifyHostKeyDNS=no",
    "-o",
    "UpdateHostKeys=no",
]


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def public_dict(self, limit: int = 20000) -> dict[str, object]:
        stdout, stdout_truncated = truncate(self.stdout, limit)
        stderr, stderr_truncated = truncate(self.stderr, limit)
        return {
            "argv": list(self.argv),
            **self.metadata,
            "returncode": self.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }

    def summary_dict(
        self,
        *,
        stdout_limit: int = 4000,
        stderr_limit: int = 2000,
    ) -> dict[str, object]:
        return {
            **self.metadata,
            "returncode": self.returncode,
            "stdout_chars": len(self.stdout),
            "stderr_chars": len(self.stderr),
            "stdout_truncated": len(self.stdout) > stdout_limit,
            "stderr_truncated": len(self.stderr) > stderr_limit,
        }


def truncate(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + f"\n[truncated after {limit} characters]", True


def ensure_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def run(
    argv: Sequence[str],
    *,
    cwd: str | Path | None = None,
    timeout: int = 60,
    text: bool = True,
) -> CommandResult:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd is not None else None,
            stdin=subprocess.DEVNULL,
            text=text,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            argv=tuple(str(arg) for arg in argv),
            returncode=completed.returncode,
            stdout=ensure_text(completed.stdout),
            stderr=ensure_text(completed.stderr),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=tuple(str(arg) for arg in argv),
            returncode=124,
            stdout=ensure_text(exc.stdout),
            stderr=ensure_text(exc.stderr) + f"\ncommand timed out after {timeout}s",
        )


def _ssh_transport_argv(
    program: str,
    device: DeviceConfig,
    ssh_config: Path | None,
) -> list[str]:
    argv = [program]
    if ssh_config:
        argv += ["-F", str(ssh_config)]
    if device.ignore_ssh_host_keys:
        argv += IGNORED_HOST_KEY_OPTIONS
    return argv


def ssh_argv(device: DeviceConfig, ssh_config: Path | None, remote: str) -> list[str]:
    argv = _ssh_transport_argv("ssh", device, ssh_config)
    argv += ["--", device.ssh_target, remote]
    return argv


def scp_to_argv(
    device: DeviceConfig,
    ssh_config: Path | None,
    local_path: Path,
    remote_path: str,
) -> list[str]:
    argv = _ssh_transport_argv("scp", device, ssh_config)
    argv += ["--", str(local_path), f"{device.ssh_target}:{remote_path}"]
    return argv


def scp_from_argv(
    device: DeviceConfig,
    ssh_config: Path | None,
    remote_path: str,
    local_path: Path,
) -> list[str]:
    argv = _ssh_transport_argv("scp", device, ssh_config)
    argv += ["--", f"{device.ssh_target}:{remote_path}", str(local_path)]
    return argv


def remote_command(argv: Iterable[str]) -> str:
    return shlex.join([str(arg) for arg in argv])


def user_bus_env(device: DeviceConfig) -> list[str]:
    return [
        "env",
        f"XDG_RUNTIME_DIR={device.user_bus_runtime_dir}",
        f"DBUS_SESSION_BUS_ADDRESS={device.user_bus_address}",
    ]
