"""Device prerequisites and the small set of optional packages setup can install."""
from __future__ import annotations

from typing import Any


# Each tuple is a requirement; multiple entries are acceptable alternatives.
DEVICE_FEATURES = {
    "commands": (("sh",), ("env",)),
    "diagnostics": (("journalctl",), ("cat",), ("dbus-send",), ("env",)),
    "screenshot": (("dbus-send",), ("env",), ("sg",), ("stat",),
                   ("install",), ("getent",), ("dirname",)),
    "touch": (("sh",), ("cat",), ("python3",)),
    "input_trace": (("sh",), ("cat",), ("evdev_trace",), ("sleep",)),
    "app_launch": (("gio",), ("getent",), ("cut",), ("nohup",),
                   ("mkdir",), ("mktemp",), ("mv",), ("cat",), ("tail",),
                   ("sleep",), ("sh",), ("env",), ("runuser", "su")),
    "browser": (("systemctl",), ("pidof",), ("ps",), ("awk",), ("grep",),
                ("invoker",), ("sailfish-browser",), ("dbus-send",),
                ("sleep",), ("sh",), ("env",), ("runuser", "su")),
    "install": (("pkcon", "rpm"),),
    "services": (("systemctl",), ("env",)),
}
DEFAULT_DEVICE_FEATURES = (
    "commands", "diagnostics", "screenshot", "touch", "app_launch", "install", "services",
)
# Base OS packages and applications are deliberately left to manual repair.
DEVICE_SETUP_PACKAGES = {"python3": "python3-base", "evdev_trace": "mce-tools"}
SESSION_FEATURES = {"diagnostics", "screenshot", "app_launch", "browser"}


def selected_features(args: dict[str, Any]) -> list[str]:
    features = args.get("features", list(DEFAULT_DEVICE_FEATURES))
    if (not isinstance(features, list) or not features
            or not all(isinstance(feature, str) and feature in DEVICE_FEATURES
                       for feature in features)):
        raise ValueError("features must be a non-empty list of supported device workflows")
    return list(dict.fromkeys(features))


def probe_tools(features: list[str]) -> list[str]:
    return sorted({tool for feature in features for group in DEVICE_FEATURES[feature]
                   for tool in group} | {"pkcon", "zypper"})


def probe_script() -> str:
    # Positional arguments keep configuration values out of shell source. This
    # probe needs only sh builtins and id; Python is not needed to diagnose it.
    return r'''set -eu
printf 'uid\t%s\n' "$(id -u)"
username=$1
bus_address=$2
shift 2
if command -v getent >/dev/null 2>&1 && getent passwd "$username" >/dev/null; then
    printf 'session_user\t1\n'
else
    printf 'session_user\t0\n'
fi
case "$bus_address" in
    unix:path=*)
        socket=${bus_address#unix:path=}
        if [ -S "$socket" ]; then printf 'session_socket\t1\n';
        else printf 'session_socket\t0\n'; fi ;;
    *) printf 'session_socket\tunknown\n' ;;
esac
for tool do
    location=$(command -v "$tool" 2>/dev/null || true)
    printf 'tool:%s\t%s\n' "$tool" "$location"
    if [ "$tool" = python3 ] && [ -n "$location" ]; then
        if python3 -c 'import os, re, struct, sys, time; sys.exit(0 if sys.version_info >= (3, 6) else 1)' >/dev/null 2>&1; then
            printf 'python3_compatible\t1\n'
        else
            printf 'python3_compatible\t0\n'
        fi
    fi
done
'''


def probe_report(features: list[str], stdout: str) -> dict[str, Any]:
    values = dict(line.split("\t", 1) for line in stdout.splitlines() if "\t" in line)
    if not values.get("uid", "").isdigit():
        raise ValueError("device prerequisite probe did not return a numeric uid")
    tools = {tool: values.get("tool:" + tool, "") for tool in probe_tools(features)}
    missing_by_feature = {
        feature: [" or ".join(group) for group in DEVICE_FEATURES[feature]
                  if not any(tools[tool] for tool in group)]
        for feature in features
    }
    missing = sorted({tool for requirements in missing_by_feature.values() for tool in requirements})
    if "touch" in features and tools["python3"] and values.get("python3_compatible") != "1":
        requirement = "Python >=3.6 with os, re, struct, sys and time modules"
        missing.append(requirement)
        missing_by_feature["touch"].append(requirement)
    packages = sorted({DEVICE_SETUP_PACKAGES[tool] for tool in missing
                       if tool in DEVICE_SETUP_PACKAGES})
    session_needed = bool(SESSION_FEATURES.intersection(features))
    session_issues = []
    if session_needed and values.get("session_user") != "1":
        session_issues.append("configured session user was not found")
    if session_needed and values.get("session_socket") == "0":
        session_issues.append("configured session-bus socket was not found")
    if session_needed and values.get("session_socket") == "unknown":
        session_issues.append("session-bus address needs manual verification")
    return {
        "features": features, "uid": int(values["uid"]), "tools": tools,
        "missing_by_feature": missing_by_feature, "missing_tools": missing,
        "installable_packages": packages,
        "manual_tools": [tool for tool in missing if tool not in DEVICE_SETUP_PACKAGES],
        "session_issues": session_issues, "ready": not missing and not session_issues,
    }
