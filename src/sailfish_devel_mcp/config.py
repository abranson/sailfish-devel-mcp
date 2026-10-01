from __future__ import annotations

from dataclasses import dataclass, field, replace
import json
import os
from pathlib import Path
from typing import Any, Mapping


DEFAULT_RUNTIME_DIR = "/run/user/100000"
DEFAULT_BUS_ADDRESS = "unix:path=/run/user/100000/dbus/user_bus_socket"
USB_DEVICE_IP = "192.168.2.15"
BUNDLED_BUILD_HELPER = (
    Path(__file__).resolve().parent / "vendor" / "build_sailfishos.py"
)
DEFAULT_ANDROID_BUILD_HOST = "android-builder"
DEFAULT_ANDROID_BUILD_SSH_TARGET = "builder@example.invalid"
DEFAULT_ANDROID_BUILD_PROJECT_DIR = ""
DEFAULT_ANDROID_BUILD_STATE_DIR = "/tmp/sailfish-devel-mcp/android-builds"


def validate_ssh_target(target: str) -> None:
    if (not isinstance(target, str) or not target or target.startswith("-")
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in target)):
        raise ValueError("SSH target must be a hostname or user@host without options or whitespace")


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    ssh_target: str
    username: str = "defaultuser"
    architecture: str = ""
    release: str = ""
    user_bus_runtime_dir: str = DEFAULT_RUNTIME_DIR
    user_bus_address: str = DEFAULT_BUS_ADDRESS
    ignore_ssh_host_keys: bool = False

    def __post_init__(self) -> None:
        validate_ssh_target(self.ssh_target)

    def public_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "ssh_target": self.ssh_target,
            "username": self.username,
            "architecture": self.architecture,
            "release": self.release,
            "user_bus_runtime_dir": self.user_bus_runtime_dir,
            "user_bus_address": self.user_bus_address,
        }


@dataclass(frozen=True)
class AndroidBuildHostConfig:
    name: str
    ssh_target: str
    project_dir: str
    state_dir: str = DEFAULT_ANDROID_BUILD_STATE_DIR

    def __post_init__(self) -> None:
        validate_ssh_target(self.ssh_target)

    def public_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "ssh_target": self.ssh_target,
            "project_dir": self.project_dir,
            "state_dir": self.state_dir,
        }


def default_android_build_hosts() -> dict[str, AndroidBuildHostConfig]:
    return {
        DEFAULT_ANDROID_BUILD_HOST: AndroidBuildHostConfig(
            name=DEFAULT_ANDROID_BUILD_HOST,
            ssh_target=DEFAULT_ANDROID_BUILD_SSH_TARGET,
            project_dir=DEFAULT_ANDROID_BUILD_PROJECT_DIR,
            state_dir=DEFAULT_ANDROID_BUILD_STATE_DIR,
        )
    }


def default_ssh_config() -> Path:
    path = Path.home() / ".ssh" / "config"
    return path if path.exists() else Path("/dev/null")


@dataclass(frozen=True)
class PathConfig:
    git_root: Path = Path.home() / "git"
    obs_root: Path = Path.home() / "OBS"
    ssh_config: Path = field(default_factory=default_ssh_config)
    build_sailfishos: Path = BUNDLED_BUILD_HELPER
    local_sdk: Path | None = None
    osc_api_alias: str = ""
    obs_servers: Mapping[str, str] = field(default_factory=dict)

    def public_dict(self) -> dict[str, object]:
        return {
            "git_root": str(self.git_root),
            "obs_root": str(self.obs_root),
            "ssh_config": str(self.ssh_config),
            "build_sailfishos": str(self.build_sailfishos),
            "local_sdk": str(self.local_sdk) if self.local_sdk else None,
            "osc_api_alias": self.osc_api_alias,
            "obs_servers": dict(self.obs_servers),
        }


@dataclass(frozen=True)
class Config:
    path: Path | None
    default_device: str
    devices: Mapping[str, DeviceConfig] = field(default_factory=dict)
    paths: PathConfig = field(default_factory=PathConfig)
    default_android_build_host: str = DEFAULT_ANDROID_BUILD_HOST
    android_build_hosts: Mapping[str, AndroidBuildHostConfig] = field(
        default_factory=default_android_build_hosts
    )

    def device(self, name: str | None = None) -> DeviceConfig:
        usb = name == "usb" or bool(name and name.startswith("usb:"))
        key = (
            self.default_device
            if name in (None, "usb")
            else name.removeprefix("usb:")
        )
        if key in self.devices:
            device = self.devices[key]
        elif key and "@" in key:
            device = DeviceConfig(name=key, ssh_target=key)
        else:
            raise KeyError(f"unknown Sailfish device: {key}")
        if usb:
            user, separator, _host = device.ssh_target.rpartition("@")
            ssh_target = f"{user}@{USB_DEVICE_IP}" if separator else USB_DEVICE_IP
            return replace(
                device,
                ssh_target=ssh_target,
                ignore_ssh_host_keys=True,
            )
        return device

    def android_build_host(self, name: str | None = None) -> AndroidBuildHostConfig:
        key = name or self.default_android_build_host
        if key in self.android_build_hosts:
            return self.android_build_hosts[key]
        if name and "@" in name:
            return AndroidBuildHostConfig(
                name=name,
                ssh_target=name,
                project_dir=DEFAULT_ANDROID_BUILD_PROJECT_DIR,
            )
        raise KeyError(f"unknown Android build host: {key}")

    def public_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path) if self.path else None,
            "default_device": self.default_device,
            "devices": {
                name: device.public_dict() for name, device in self.devices.items()
            },
            "paths": self.paths.public_dict(),
            "default_android_build_host": self.default_android_build_host,
            "android_build_hosts": {
                name: host.public_dict()
                for name, host in self.android_build_hosts.items()
            },
        }


def default_config_path() -> Path:
    if "SAILFISH_MCP_CONFIG" in os.environ:
        return Path(os.environ["SAILFISH_MCP_CONFIG"]).expanduser()
    return Path.home() / ".config" / "sailfish-devel-mcp" / "config.json"


def load_config(path: str | os.PathLike[str] | None = None) -> Config:
    config_path = Path(path).expanduser() if path else default_config_path()
    raw: dict[str, Any] = {}

    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict):
            raise ValueError(f"{config_path} must contain a JSON object")
        raw = loaded

    devices = _load_devices(raw.get("devices", {}))
    if not devices:
        default_name = os.environ.get("SAILFISH_MCP_DEFAULT_DEVICE", "device")
        devices = {
            default_name: DeviceConfig(
                name=default_name,
                ssh_target=os.environ.get("SAILFISH_MCP_SSH_TARGET", "root@device"),
            )
        }

    default_device = str(raw.get("default_device") or next(iter(devices)))
    paths = _load_paths(raw.get("paths", {}))
    android_build_hosts = _load_android_build_hosts(raw.get("android_build_hosts", {}))
    default_android_build_host = str(
        raw.get("default_android_build_host") or next(iter(android_build_hosts))
    )
    return Config(
        path=config_path if config_path.exists() else None,
        default_device=default_device,
        devices=devices,
        paths=paths,
        default_android_build_host=default_android_build_host,
        android_build_hosts=android_build_hosts,
    )


def _load_devices(raw_devices: Any) -> dict[str, DeviceConfig]:
    if not isinstance(raw_devices, dict):
        raise ValueError("devices must be a JSON object")

    devices: dict[str, DeviceConfig] = {}
    for name, value in raw_devices.items():
        if isinstance(value, str):
            value = {"ssh_target": value}
        if not isinstance(value, dict):
            raise ValueError(f"device {name!r} must be a string or object")
        ssh_target = str(value.get("ssh_target") or name)
        devices[str(name)] = DeviceConfig(
            name=str(name),
            ssh_target=ssh_target,
            username=str(value.get("username") or "defaultuser"),
            architecture=str(value.get("architecture") or ""),
            release=str(value.get("release") or ""),
            user_bus_runtime_dir=str(
                value.get("user_bus_runtime_dir") or DEFAULT_RUNTIME_DIR
            ),
            user_bus_address=str(value.get("user_bus_address") or DEFAULT_BUS_ADDRESS),
        )
    return devices


def _load_android_build_hosts(raw_hosts: Any) -> dict[str, AndroidBuildHostConfig]:
    if not isinstance(raw_hosts, dict):
        raise ValueError("android_build_hosts must be a JSON object")

    hosts: dict[str, AndroidBuildHostConfig] = {}
    for name, value in raw_hosts.items():
        if isinstance(value, str):
            value = {"ssh_target": value}
        if not isinstance(value, dict):
            raise ValueError(f"android build host {name!r} must be a string or object")
        hosts[str(name)] = AndroidBuildHostConfig(
            name=str(name),
            ssh_target=str(value.get("ssh_target") or name),
            project_dir=str(
                value.get("project_dir") or DEFAULT_ANDROID_BUILD_PROJECT_DIR
            ),
            state_dir=str(value.get("state_dir") or DEFAULT_ANDROID_BUILD_STATE_DIR),
        )

    if not hosts:
        name = os.environ.get("SAILFISH_MCP_ANDROID_BUILD_HOST", DEFAULT_ANDROID_BUILD_HOST)
        hosts[name] = AndroidBuildHostConfig(
            name=name,
            ssh_target=os.environ.get(
                "SAILFISH_MCP_ANDROID_BUILD_SSH_TARGET",
                DEFAULT_ANDROID_BUILD_SSH_TARGET,
            ),
            project_dir=os.environ.get(
                "SAILFISH_MCP_ANDROID_BUILD_PROJECT_DIR",
                DEFAULT_ANDROID_BUILD_PROJECT_DIR,
            ),
            state_dir=os.environ.get(
                "SAILFISH_MCP_ANDROID_BUILD_STATE_DIR",
                DEFAULT_ANDROID_BUILD_STATE_DIR,
            ),
        )
    return hosts


def _load_paths(raw_paths: Any) -> PathConfig:
    if not isinstance(raw_paths, dict):
        raise ValueError("paths must be a JSON object")
    raw_obs_servers = raw_paths.get("obs_servers", {})
    if not isinstance(raw_obs_servers, dict):
        raise ValueError("paths.obs_servers must be a JSON object")
    obs_servers: dict[str, str] = {}
    for name, alias in raw_obs_servers.items():
        if not isinstance(name, str) or not name:
            raise ValueError("paths.obs_servers names must be non-empty strings")
        if not isinstance(alias, str) or not alias:
            raise ValueError(
                f"paths.obs_servers.{name} must be a non-empty string"
            )
        obs_servers[name] = alias
    defaults = PathConfig()
    raw_local_sdk = raw_paths.get("local_sdk") or os.environ.get("SAILFISH_MCP_LOCAL_SDK")
    return PathConfig(
        git_root=Path(
            str(
                raw_paths.get("git_root")
                or os.environ.get("SAILFISH_MCP_GIT_ROOT")
                or defaults.git_root
            )
        ).expanduser(),
        obs_root=Path(
            str(
                raw_paths.get("obs_root")
                or os.environ.get("SAILFISH_MCP_OBS_ROOT")
                or defaults.obs_root
            )
        ).expanduser(),
        ssh_config=Path(
            str(
                raw_paths.get("ssh_config")
                or os.environ.get("SAILFISH_MCP_SSH_CONFIG")
                or defaults.ssh_config
            )
        ).expanduser(),
        build_sailfishos=Path(
            str(
                raw_paths.get("build_sailfishos")
                or os.environ.get("SAILFISH_MCP_BUILD_HELPER")
                or defaults.build_sailfishos
            )
        ).expanduser(),
        local_sdk=Path(str(raw_local_sdk)).expanduser() if raw_local_sdk else None,
        osc_api_alias=str(
            raw_paths.get("osc_api_alias")
            or os.environ.get("SAILFISH_MCP_OSC_API_ALIAS")
            or defaults.osc_api_alias
        ),
        obs_servers=obs_servers,
    )
