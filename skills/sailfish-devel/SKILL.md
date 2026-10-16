---
name: sailfish-devel
description: Deploy and debug SailfishOS devices, inspect UI and logs, and coordinate Android or OBS jobs with the Sailfish Devel MCP. Use build-sailfishos for RPM build configuration.
---

# Sailfish development

Use the Sailfish Devel MCP's typed device and job tools when available.
Use `sailfish_doctor` for environment problems. Its `host_runtime.restart_needed`
flags source changes since startup; restart the MCP connection before relying on
updated host code when true. `sailfish_devices` lists configured
aliases, not measured device state. Query the device when its current state matters.

For a new device, use `sailfish_device_setup` with the relevant `features` to
check executable availability and session configuration. Its default only
checks state. Set `install_missing=true` only when installing optional device
packages is authorized; it can install missing Python and input-tracing tools
from existing repositories. Wait for the build-job receipt to complete and read
the final prerequisite report before dependent actions. Missing base OS tools,
applications, permissions and session configuration need manual repair.

## Optional device companion

Use `sailfish_device_setup` with `companion=check` to inspect installation or
`companion=deploy` to install/update. Always request explicit user permission
before first installation on each device. Before asking, warn that the companion
is intended for dedicated development/test devices and should not be installed
on personal or primary phones containing real accounts or sensitive data.
The companion is a root system service. Journal/D-Bus captures can expose private application/account data to the host
MCP client and model context. Set `confirm_companion_install=true`
only after that approval. Updating a recognized installation requires no renewed
permission. Neither a general device task nor permission on another device
counts as first-install approval. Default setup performs no companion deployment.

Existing host device tools prefer a compatible companion and retain SSH fallback
for devices without an available companion. Never retry a failed companion
operation over SSH; it may already have performed its side effects. Device jobs
retain their selected backend and host receipt; use the normal command status,
cancel and CLI waiter interfaces. Job listings are last-known snapshots; query
an individual job for current state. Updates/stops/removal refuse active jobs.
Session operations run as the configured user; journal capture can use root access
with `scope=user` (UID/user-unit filtered) or `scope=system`.

The companion exits after one idle hour, without interrupting active commands
or jobs. Each capture also expires after one hour; polling does not extend it.
Installed companions start on demand for routed work or capture_start. Management
stop pauses this persistently; start or deployment resumes it.

Use `sailfish_device_companion_manage` for status/start/stop/remove. Start only
narrow, authorized captures; capture is off by default. Save the events result's
`instance` and `next_after` and pass them as `instance` and `after` on the next
read. Check `reset` and `dropped` before assuming the history is complete.
Capture survives SSH disconnects but not service restart/update or reboot. The service is not enabled at boot.
Use `wait_service` or bounded `events` waiting instead of repeated remote polls.

## Deploy and inspect

- Install a dependency set with one `sailfish_device_install_rpm` call using
  `rpm_paths`. The default is detached: wait for successful job completion before
  restarting a service or launching an app. Status/cancel use the build-job tools.
- Launch installed desktop entries with `sailfish_device_app_launch`, then check
  Lipstick's topmost PID and screenshot when foreground rendering matters. A
  launcher receipt alone does not prove the app became visible.
- Screenshot paths must be inside the device user's home. Supply `local_path`
  when the image must be inspected locally. Use a current screenshot for touch
  coordinates; the touch tools accept raw device coordinates, not normalized ones.
- Use `sailfish_device_touch_workflow` for before/action/after inspection. Request
  touchscreen discovery only when selecting an input device is uncertain.
- Narrow journal reads by unit, time and grep; narrow process maps with `contains`.
  Request bounded excerpts before retrieving more logs.

## Commands and jobs

Short session commands use an argv list and do not perform shell parsing. Set
`run_as_user` when the command must execute as the configured session user.
Use `sailfish_device_command_start` for tracing, GDB or work exceeding 15 seconds.
Its status/cancel tools are separate from build status/cancel tools.

For long jobs, start detached, confirm startup with one bounded check, then
arrange a quiet scheduled follow-up in the current task unless the user opts out,
and return to the user.
Reuse an existing monitor for the job. Inspect a bounded log excerpt at each
check, use progress to choose the next interval (normally 5–15 minutes), and
notify once after verifying completion or failure. Remove the completed monitor.
If scheduling is unavailable, say so; do not imply a monitor exists.

When the user explicitly requests waiting, run `sailfish-devel-jobs wait --kind
build|device|android --job-id ID` (or `bin/sailfish-devel-jobs` from the checkout)
in one quiet terminal process. For Android, include `--host` and any nondefault
remote `--state-dir`. Wait expiration does not cancel the job. Do not loop through
model turns issuing short status requests. Occasional status calls use `lines=0`
and `after_revision` to suppress unchanged details; scheduled progress checks
also need a bounded log excerpt. Retrieve local log pages using `log_offset` and
`max_bytes`, following `next_offset`.

Use `sailfish_android_build` for configured Android/AppSupport hosts and
`sailfish_obs_watch` for detached provider-native OBS watching. Follow the project's
recorded OBS server, package set and branch mapping. Use `$build-sailfishos` when
choosing RPM build targets, snapshot inputs or packaging options.

If an expected MCP tool loses its transport, inspect
`~/.local/state/sailfish-devel-mcp/server.log`, report the failure and stop instead
of silently switching to SSH. When MCP is unavailable from the outset, follow the
machine's SSH instructions and preserve its configured user-session environment.
