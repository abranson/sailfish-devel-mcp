---
name: sailfish-devel
description: Deploy and debug SailfishOS devices, inspect UI and logs, and coordinate Android or OBS jobs with the Sailfish Devel MCP. Use build-sailfishos for RPM build configuration.
---

# Sailfish development

Use the Sailfish Devel MCP's typed device and job tools when available.
Use `sailfish_doctor` for environment problems; `sailfish_devices` lists configured
aliases, not measured device state. Query the device when its current state matters.

For a new device, use `sailfish_device_setup` with the relevant `features` to
check executable availability and session configuration. Its default only
checks state. Set `install_missing=true` only when installing optional device
packages is authorized; it can install missing Python and input-tracing tools
from existing repositories. Wait for the build-job receipt to complete and read
the final prerequisite report before dependent actions. Missing base OS tools,
applications, permissions and session configuration need manual repair.

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

For long jobs, run `sailfish-devel-jobs wait --kind build|device|android --job-id ID`
(or the MCP checkout's `bin/sailfish-devel-jobs`) in one quiet terminal process.
For Android, include `--host` and any nondefault remote `--state-dir`. The waiter
prints once on completion or failure; wait expiration does not cancel the job.
Do not loop through model turns issuing short status requests. Occasional status
calls use `lines=0` and `after_revision` to suppress unchanged details. Retrieve
local log pages using `log_offset` and `max_bytes`, following `next_offset`.

Use `sailfish_android_build` for configured Android/AppSupport hosts and
`sailfish_obs_watch` for detached provider-native OBS watching. Follow the project's
recorded OBS server, package set and branch mapping. Use `$build-sailfishos` when
choosing RPM build targets, snapshot inputs or packaging options.

If an expected MCP tool loses its transport, inspect
`~/.local/state/sailfish-devel-mcp/server.log`, report the failure and stop instead
of silently switching to SSH. When MCP is unavailable from the outset, follow the
machine's SSH instructions and preserve its configured user-session environment.
