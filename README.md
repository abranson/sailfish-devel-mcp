# Sailfish Devel MCP

Host-side Model Context Protocol server for Sailfish OS development workflows.

This first iteration is dependency-free: it implements MCP over stdio directly
with Python's standard library and exposes typed tools around commands that are
easy to get wrong during day-to-day Sailfish work.

## Scope

The server currently exposes tools for:

- Sailfish device access over SSH
- device prerequisite checks and opt-in installation of missing optional tools
- defaultuser session-bus calls
- Lipstick screenshots
- touchscreen discovery and tap/swipe injection
- combined screenshot, touchscreen discovery, and touch injection workflows
- topmost window PID lookup
- process map inspection
- journal log reads
- RPM copy/install on a device
- system and user service management
- short and detached user-session command execution with the configured D-Bus environment
- desktop-entry application launch as the configured session user
- Sailfish Browser launch/debug helpers
- preflighted Docker/mb2 RPM builds through the vendored `build-sailfishos` helper
- cancellable local and remote Android/AppSupport build jobs
- installed SDK repository metadata refresh
- OBS result and build-log lookup through `osc`
- repository status and search under the configured git root
- RPM spec metadata summaries
- QML translation search and Sailfish ternary translation checks

The committed configuration template defaults are deliberately generic.
Device tools default to the placeholder SSH target `root@device`, the Sailfish
user-session bus at `/run/user/100000/dbus/user_bus_socket`, `~/git` as the
local source root, `~/OBS` as the OBS checkout root, and the vendored build
helper at
`src/sailfish_devel_mcp/vendor/build_sailfishos.py`. Put a config file at
`~/.config/sailfish-devel-mcp/config.json` or pass `--config` to provide your
real device and OBS settings. Device entries can also carry the preferred user,
architecture, and configured release label. If an installed SDK is available,
set `paths.local_sdk` to its `sdk-chroot` path; builds will use it when it has a
target matching the requested release and architecture, otherwise they fall
back to a matching tag in the third-party coderus Docker mirror. Neither a
configured device label nor mirror tag availability independently establishes
the current official SailfishOS release or SDK target.

For a device attached over USB, pass `usb` as the device argument to use the
configured default device, or `usb:<name>` when the user supplies a device
name. The MCP keeps that device's user and session metadata but connects to
`192.168.2.15` without checking or storing SSH host keys. It trusts the supplied
name and does not resolve it through DNS, so no separate validation connection
is made.

Generic Python configuration code is tracked and works in a clean checkout.
Keep all machine-specific values in `~/.config/sailfish-devel-mcp/config.json`
or its environment overrides. No Python bootstrap copy is needed.

## Host prerequisites

Use a Linux host with Python **3.10 or newer**. The server has no third-party
Python runtime dependencies. Detached job supervision uses POSIX process groups
and Linux `/proc`. The following programs are needed only for the workflows
listed; installing every optional tool is unnecessary.

| Workflow | Host requirements |
| --- | --- |
| Run from the checkout | `python3`, POSIX `sh`, `dirname`, `mkdir`, `touch`, and `date` for the logging wrapper |
| Install the Python package | `pip` and setuptools >=61 for packaging; `python3 -m pip install .` installs both CLI entry points |
| Device commands and deployment | OpenSSH `ssh`; `scp` for RPM copies and screenshot downloads; SSH credentials and a reachable device |
| Repository inspection | `git`; `rg` (ripgrep) for searches, with `grep` as a repository-search fallback |
| QML translation search | `rg`; the ternary-comment checker itself needs only Python |
| RPM builds and SDK refresh | A running Docker engine accessible to your user, `git`, and `bash`; ACL tools (`setfacl`) for Docker builds that need container write access |
| Installed SDK builds | A configured Sailfish Platform SDK `sdk-chroot`, registered architecture targets, and an appropriate Docker wrapper image; `sdk-manage`, `mb2`, `sb2`, `zypper`, RPM and build dependencies live inside the SDK |
| OBS results and logs | `osc`, with the selected server and credentials configured in your `.oscrc` |
| Android/AppSupport builds | `ssh`; a separate configured Linux build host with its Android tree and build dependencies |

Run the MCP tool `sailfish_doctor` to report local command availability, helper
provenance and installed SDK targets. It does not connect to devices, test Docker
daemon access, or install host packages. Install host tools through your Linux
distribution; the package names differ between distributions. Check RPM build
requirements in each project's spec file and Android requirements in its tree's
documentation.

The remote Android build host also needs `sh`, the selected `bash` or `sh`,
`nohup`, `setsid`, `base64`, `date`, `mkdir`, `chmod`, `cat`, `sed`, `cut`,
`sort`, `tail`, and `sleep`, plus Linux `/proc`. These support job bookkeeping
and cancellation; the build command may require additional tools.

## Device prerequisites and optional setup

Enable Sailfish developer mode and SSH access before using device tools. SSH
authentication and root access must be configured by the device owner. Set the
device's `username` and session-bus address in the local configuration: older
devices can use `nemo` rather than `defaultuser`, and the user ID can differ.
Start the graphical user session before checking Lipstick or session-bus tools.
See the [Sailfish developer-mode instructions](https://docs.sailfishos.org/Support/Help_Articles/Enabling_Developer_Mode/)
and [D-Bus reference](https://docs.sailfishos.org/Reference/Core_Areas_and_APIs/D-Bus_APIs/).

| Feature passed to `sailfish_device_setup` | Device requirements |
| --- | --- |
| `commands` | `sh` and `env`; arbitrary commands need their own executables |
| `diagnostics` | `journalctl`, `cat`, `dbus-send`, `env`; the configured session bus and Lipstick for topmost PID queries; readable `/proc/<pid>/maps` for process maps |
| `screenshot` | `dbus-send`, `env`, `sg`, `stat`, `install`, `getent`, `dirname`; Lipstick's screenshot API and access to the `privileged` group |
| `touch` | Python >=3.6 with standard-library `os`, `re`, `struct`, `sys` and `time`; `sh`, `cat`; readable `/proc/bus/input/devices` and permission to write the selected `/dev/input/event<N>` |
| `input_trace` | Optional `evdev_trace` from `mce-tools`, plus `sh`, `cat`, `sleep`; `timeout` is used when present, with a bounded fallback otherwise |
| `app_launch` | `gio`, `getent`, `cut`, `nohup`, `mkdir`, `mktemp`, `mv`, `cat`, `tail`, `sleep`, `sh`, `env`, and either `runuser` or `su`; installed desktop entries and a graphical user session |
| `browser` | `systemctl`, `pidof`, `ps`, `awk`, `grep`, `invoker`, `sailfish-browser`, `dbus-send`, `sleep`, `sh`, `env`, and either `runuser` or `su`; Sailfish Browser and its booster/session environment |
| `install` | `pkcon` for the default installer or `rpm` when explicitly selected; an SSH file-transfer subsystem compatible with the host's `scp`; package-install privileges |
| `services` | `systemctl`, `env`; permissions for the selected system or user service |

The prerequisite probe itself requires `sh` and `id`. `dbus-send` is supplied by
[`dbus`](https://github.com/sailfishos/dbus/blob/master/rpm/dbus.spec), and `gio`
is supplied by [`glib2`](https://github.com/sailfishos/glib2/blob/master/rpm/glib2.spec)
in current Sailfish packaging. Base OS tools, missing applications, permissions,
and session configuration require manual repair. Command availability and a
session socket do not prove that every device API or touch input works.

Call `sailfish_device_setup` with `install_missing` omitted or `false` to check
a device without installing anything:

```json
{"device": "phone", "features": ["touch", "app_launch"]}
```

The result lists discovered executables, missing requirements, session issues,
and optional packages that could be installed. The default features are
`commands`, `diagnostics`, `screenshot`, `touch`, `app_launch`, `install`, and
`services`. Select `input_trace` or `browser` explicitly when needed.

To install supported missing optional tools, explicitly opt in:

```json
{"device": "phone", "features": ["touch", "input_trace"], "install_missing": true}
```

Setup requires a root SSH login and `pkcon` or `zypper`. It installs only missing
`python3-base` (for Python) and `mce-tools` (for `evdev_trace`) from the device's
existing repositories, then checks again. Package dependencies are resolved by
the device package manager. It does not add repositories, enable SSH, change
accounts or permissions, or repair base OS packages. Package availability can
vary with the configured Sailfish release. The mappings follow the
[Python spec](https://github.com/sailfishos/python3/blob/master/rpm/python3.spec)
and [Sailfish touch documentation](https://docs.sailfishos.org/Reference/Architecture/#touch).

Installation returns a detached job by default. Check `sailfish_build_status`
or use `sailfish-devel-jobs wait --kind build --job-id JOB_ID`; the completed
status includes the final report under `device_setup` and its JSON `result_path`.
`sailfish_build_cancel` requests
cancellation, but interrupting SSH does not roll back a package transaction.
`wait=true` requests synchronous operation for controlled diagnostics.

## Optional device companion

**Development/test devices only. Do not install this companion on a personal
or primary phone containing real accounts or sensitive data.** It runs as root
and can execute privileged development commands. Journal/D-Bus captures, screenshots
and diagnostics can include private data returned to the host MCP client and model
context. Present this warning before requesting first-install permission.

The host MCP remains the coordinator for builds, OBS, repository work and file
transfers. The optional Python 3.6+ standard-library companion runs as a **system
service**, with a root-only Unix socket reached over existing SSH access. It has
no TCP listener. Session D-Bus calls, app launches and user-service operations run
as the configured graphical user with that user's home and bus environment.

Use `sailfish_device_setup` for installation and updates:

```json
{"device": "phone", "features": ["companion"], "companion": "check"}
```

Always request permission before first installation on each device. Only after
approval, deploy with:

```json
{"device": "phone", "features": ["companion"], "companion": "deploy", "confirm_companion_install": true}
```

Updates to recognized installations need no renewed permission; omit the
confirmation flag. A recognized earlier user-service installation is migrated:
setup verifies root-service readiness before stopping/removing the old user
service. User-owned companion source is never executed as root during migration.
Unknown files/symlinks are refused. The confirmation flag records the caller's
assertion of approval, not an independent authentication mechanism.

Deployment requires root SSH and writes:

- `/opt/sailfish-devel-companion/{agent.py,owner,session.json}`
- `/etc/systemd/system/sailfish-devel-companion.service`
- Runtime socket/lock in `/run/sailfish-devel-companion/`, with a separate
  `/run/sailfish-devel-companion.control` lifecycle lock.
- Detached job state/logs under `/var/lib/sailfish-devel-companion/jobs/`.

Code, configuration, socket and job directories are private to root. Setup starts
or restarts the service and returns the deployed source SHA-256. It does not enable
boot autostart or start capture. An installed companion starts on demand for
routed device work or a new capture. It exits successfully after **one hour of
inactivity**, so systemd does not restart it. Active requests and detached jobs
prevent idle shutdown and reset the idle period. Capture output does not count
as activity; each capture expires after **one hour**, even if clients keep polling.
Restart capture explicitly for a longer session. Idle shutdown discards the
in-memory event history; detached job records remain on disk.

Management `stop` pauses on-demand startup persistently; `start` or a deployment
update resumes it. Status inspection does not start a stopped service. A failed
on-demand start selects SSH fallback before any requested operation executes.
The system service is independent of the graphical
session; session-dependent tools still require that session to be available.
Optional Python installation still requires `install_missing=true`. Ordinary
setup defaults perform no installation. Setup, recovery and RPM transfer/install
retain their host implementations and do not depend on a working companion.

### Existing device tools and fallback

Public host tool names and arguments are preserved. Journal reads, process maps,
topmost PID, D-Bus calls, short commands, screenshots/touch, app/browser launch,
service control and detached device commands prefer a compatible companion.
Absent, incompatible or explicitly paused companions select the retained SSH implementation
**before execution**. A protocol/transport error or failed operation after selecting
the companion is reported, never retried over SSH. No automatic installation occurs.
Root-only socket access does not elevate a non-root SSH account; it uses fallback.

Journal/process-map filtering runs on the device. Screenshot/touch workflows run
under one device-local operation lock; file downloads remain host-side and happen
after the device sequence. A download failure does not replay already-performed
touch input. App launch adds observed foreground PID/verification where the desktop
entry's executable can be identified; submission alone still does not prove visible
rendering. Service calls include local state and bounded failure logs. Operations
that start/stop the companion itself use SSH to avoid severing their own RPC.

Detached commands run under device-owned supervisors, survive host/SSH disconnects,
and terminate their process groups on cancellation/timeout, including children
whose leader has exited. Durable host receipts keep the existing job ID and
status/cancel/CLI interface. Individual status reads contact the recorded device;
listings show the last known snapshot. Jobs never switch backend after submission.
Logs stay on the device and are retrieved in bounded pages/excerpts. Restart/reboot
interruption is reported as a lost supervisor, not success. Managed stop, remove
and update refuse while jobs are active; job submission and management share a
lock. Completed job evidence is retained on companion removal.

### Capture tools

All tools below have the prefix `sailfish_device_companion_`:

| Suffix | Purpose |
| --- | --- |
| `manage` | Inspect installation or start/stop/remove the service |
| `status` | Running version, API capabilities, UID, session user and capture state |
| `capture_start` | One journal unit (`source=journal`, `unit=example.service`, `scope=user/system`, default user), or D-Bus interface (`source=dbus`, `interface=org.example.Interface`, `bus=session/system`) |
| `capture_stop` | Stop collection, retaining captured history |
| `events` | Read `instance`/`after` cursor pages, `limit` 1–100, optional `wait_seconds` 0–10 |
| `wait_service` | Wait for `unit` to reach `active/inactive/failed`, `scope=user/system`, up to ten seconds |

Root journal capture reads system storage directly; user scope filters by the
configured user's UID and user unit, so it works even without separate per-user
journal files. Session D-Bus capture drops to the graphical user. Capture is off
initially; a second capture is refused until the first is stopped. D-Bus output
is raw text lines. Inspect status/events for command failures and policy denials.

History is capped at 512 records of at most 4096 characters each. It survives SSH
disconnects, but not companion restart/update or reboot. Save `instance` and
`next_after`; `reset` reports a new instance and `dropped` reports overflow. Pages
are also bounded to 64 KiB of record text. Synchronous command output is bounded
to 2 MiB per stream, with truncation reported; detached logs remain complete.

For a direct MCP client, execute `/opt/sailfish-devel-companion/agent.py --stdio`
as root over SSH. It bridges the five public companion MCP tools to the existing
service. Internal execution/job RPCs are private to the root socket and support
the existing host tools. Removal deletes only recognized installation files,
stops capture, and preserves unexpected files and completed job evidence.

## Trust and privacy

This is local development tooling intended for a trusted MCP client running on
your own workstation. It communicates over stdio and has no network listener.
The client invokes tools using your host account, SSH credentials and OBS
credentials. Tool annotations describe effects; they do not enforce permissions
or provide an approval layer.

Device command tools can execute arbitrary programs. Their default identity is
the SSH login account, often root; setting the session environment does not
change that identity. Select `run_as_user=true` when execution should use the
configured Sailfish user. Android builds intentionally accept shell commands.
Configured aliases are convenient names, not a host allowlist: explicit
`user@host` targets are also supported. Target strings cannot contain SSH
options or whitespace.

RPM builds and SDK maintenance use privileged Docker containers. Installed SDK
builds mount the host user's home directory and the SDK read-write. Build only
trusted source and images, including the optional third-party SDK mirror.
Repository path checks constrain direct file operations; they do not sandbox
build scripts or arbitrary device commands. The explicit `chmod` permission
fallback broadens file permissions; prefer ACL support and the default error
behaviour when ACL tools are unavailable.

Non-USB SSH connections follow the configured SSH host-key policy. USB mode
connects to `192.168.2.15` and deliberately disables host-key checking and storage
to support changing devices at that address. Use it only for a device connection
you trust.

By default, SSH and SCP use `~/.ssh/config` when it exists, or `-F /dev/null`
when it is absent. Both choices skip the system SSH configuration; OpenSSH's
built-in defaults, including normal non-USB host-key checks, still apply.
An explicit `paths.ssh_config` must name an existing file; a missing explicit
file remains an error. This policy applies to device and Android connections.

Tool output is returned to the MCP client and may enter a model's context.
Effective configuration includes private hostnames, usernames, source paths and
OBS mappings. Screenshots, journals, source matches and job logs can contain
private data; commands can contain credentials supplied by callers. Keep real
configuration, credentials, task notes, screenshots and runtime logs out of
source releases and public bug reports. The server's request logs record
argument names rather than tool argument values, but job logs and verbose
results retain command/output details. Configure the client's tool approvals
to suit your workflow.

## Running

From a checkout:

```sh
/path/to/sailfish-devel-mcp/bin/sailfish-devel-mcp
```

To inspect the effective configuration:

```sh
/path/to/sailfish-devel-mcp/bin/sailfish-devel-mcp --dump-config
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "sailfish-devel": {
      "command": "/path/to/sailfish-devel-mcp/bin/sailfish-devel-mcp"
    }
  }
}
```

The wrapper writes startup, shutdown, MCP request, and tool-call logs to
`~/.local/state/sailfish-devel-mcp/server.log` by default. Override the log
directory with `SAILFISH_DEVEL_MCP_LOG_DIR`. If the MCP client uses a different
server label, set `SAILFISH_DEVEL_MCP_SERVER_LABEL` in the client environment so
the wrapper startup line includes the same label.

## Configuration

Example:

```json
{
  "default_device": "phone",
  "devices": {
    "phone": {
      "ssh_target": "root@phone",
      "username": "defaultuser",
      "architecture": "aarch64",
      "release": "live",
      "user_bus_runtime_dir": "/run/user/100000",
      "user_bus_address": "unix:path=/run/user/100000/dbus/user_bus_socket"
    }
  },
  "paths": {
    "git_root": "~/git",
    "obs_root": "~/OBS",
    "ssh_config": "~/.ssh/config",
    "local_sdk": "/srv/mer/sdks/sfossdk/sdk-chroot",
    "osc_api_alias": "primary",
    "obs_servers": {
      "primary": "primary",
      "community": "community"
    }
  },
  "default_android_build_host": "android-builder",
  "android_build_hosts": {
    "android-builder": {
      "ssh_target": "user@android-build-host"
    }
  }
}
```

## Tool Notes

The server keeps local paths scoped to the configured git root, OBS checkout
root, and `/tmp` for tools that read or write files. Device access still uses
SSH, so the usual SSH prompts, permissions, and command failures are surfaced
as tool results.

Mutating tools are annotated as non-read-only:

- `sailfish_device_setup` (conservatively annotated because installation is optional)
- `sailfish_device_lipstick_screenshot`
- `sailfish_device_touch`
- `sailfish_device_touch_workflow`
- `sailfish_device_user_bus_call`
- `sailfish_device_user_session_command`
- `sailfish_device_command_start`
- `sailfish_device_command_cancel`
- `sailfish_device_install_rpm`
- `sailfish_device_restart_service`
- `sailfish_device_app_launch`
- `sailfish_device_browser_launch`
- `sailfish_build_rpm`
- `sailfish_build_cancel`
- `sailfish_android_build`
- `sailfish_android_build_cancel`
- `sailfish_sdk_refresh_metadata`

`sailfish_device_lipstick_screenshot` defaults to
`~/Pictures/Screenshots/lipstick-<timestamp>.png` under `/home/<username>`,
where `username` comes from the device config. Lipstick rejects screenshot save
paths outside the home directory. When that directory is missing, the tool
derives ownership with `stat -L`, creates `Pictures` as that owner/group with
mode `775`, and creates `Pictures/Screenshots` as that owner and the
`privileged` group with mode `755` when the group exists.

`sailfish_device_touch` supports `discover`, `tap`, and `swipe`. Discovery
prints `/proc/bus/input/devices` and can also run `evdev_trace -i` when
`include_evdev_trace` is true. Tap and swipe auto-select a likely touchscreen
input event device unless `input_device` is supplied. Coordinates are raw
input/display coordinates, so pair this tool with a current screenshot when
choosing points.

`sailfish_device_touch_workflow` wraps the common UI-debugging sequence:
capture a Lipstick screenshot, optionally list touch devices, inject a tap or
swipe, and optionally capture a second screenshot. It returns each step's
structured result separately.

`sailfish_device_user_session_command` runs an argv command with
`XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` set from the configured device.
Set `run_as_user` when the command should execute as the configured Sailfish
username through `runuser` or `su`. Command tools return compact metadata and
bounded output by default; set `verbose` only when the full command, stdout, and
stderr are needed. This synchronous tool is limited to 15 seconds.

Use `sailfish_device_command_start` for GDB, tracing, or any command that might
run longer than 15 seconds. It starts a detached host-side SSH process and
returns a job id immediately, so the command survives the MCP request and stdio
server exiting. Use scheduled follow-ups for long jobs, or the CLI waiter below
when explicitly waiting. For occasional checks, use
`sailfish_device_command_status` with `lines=0` and at most 15 `wait_seconds`. Terminal
failures include a bounded log excerpt automatically. Full logs remain under
the local MCP state directory in `device-commands/<job-id>/command.log`. Use
`sailfish_device_command_cancel` to ask the owning supervisor to terminate the
SSH process group.

`sailfish_device_install_rpm` accepts either `rpm_path` for one local RPM or
`rpm_paths` for a dependency set. With `rpm_paths`, the tool copies every RPM to
the remote `remote_dir` and runs one `pkcon install-local` or `rpm -Uvh`
command with all copied files, so dependencies can be resolved together.

`sailfish_device_app_launch` launches an installed desktop entry using `gio`,
as the configured device user from their passwd home directory. For example:

```json
{"device": "my-device", "desktop_file": "sailfish-browser.desktop"}
```

A basename resolves under `/usr/share/applications`; an absolute device path
ending in `.desktop` is also accepted. No URL is required. It does not kill
running apps, restart boosters, or change preferences. The process detaches
with stdin/stdout/stderr redirected, avoiding an SSH timeout when app children
retain the connection. `wait_seconds` (0–5, default 1) checks for immediate
launcher failure; `timeout` (up to 15 seconds) must exceed it.

The receipt includes `submitted`, the launch supervisor PID (not the app PID),
`launch_exit_code` if already available, and private `remote_log`/`remote_status`
paths under the user's `~/.cache/sailfish-devel-mcp/launch.*` directory. Read those
paths with device commands for later failures and remove that specific directory
when its evidence is no longer needed. Submission or `gio` exit zero does not
prove foreground activation/rendering: check Lipstick's topmost PID and a
screenshot separately. This desktop-entry path was validated manually for Browser
on a Sailfish device; it does not claim to execute all of Lipstick's icon/switcher logic.

`sailfish_device_browser_launch` stops the browser booster service and stale
browser/firejail PIDs when requested, launches Sailfish Browser through
`invoker` with the display and user-session environment, then queries Lipstick
for the topmost PID and checks whether that process has `libxul.so` mapped.

`sailfish_build_rpm` can use a configured device's `architecture` and `release`
as defaults when the call includes `device`. If `paths.local_sdk` is set, the
build defaults to `live` and first checks the installed SDK targets. `live` uses
the unversioned local target for the requested architecture, for example
`aarch64`. A named production release is used only when passed explicitly
through the tool arguments, environment, or device config; it uses a matching
versioned local target when available, and otherwise falls back to a matching
tag in the third-party `coderus/sailfishos-platform-sdk` Docker mirror. Tags in
that mirror indicate image availability; they do not identify the current
official SailfishOS release or SDK target. The wrapper image defaults to
`sailfish-sdk-build-engine:$USER` and can be overridden with
`SAILFISH_SDK_BUILD_ENGINE_IMAGE`.

Use `sailfish_build_preflight` to validate backend, image/target selection,
architectures, local RPM inputs, pull policy, VCS behavior, and artifact paths
without pulling an image or changing the project. `sailfish_build_rpm` accepts
the same `backend`, `local_sdk`, `target`, `pull_policy`, `no_vcs_apply`, and
`allow_untrusted_rpms` controls. An explicitly selected `local` backend does
not silently fall back to Docker. Asynchronous jobs use confined UUID job
directories and expose helper metadata and RPM paths through
`sailfish_build_status`; use `sailfish_build_cancel` to terminate the tracked
process group. Successful builds run the helper in quiet mode while retaining
the complete job log. For occasional status checks, use `lines=0` and
`after_revision` to suppress unchanged output. Scheduled progress checks need
bounded log evidence to choose the next interval; follow the long-job policy
below instead of repeatedly calling short status waits. A terminal failure
includes a bounded diagnostic excerpt; request more only when needed. Status waits are capped at
15 seconds so a monitoring request stays comfortably below the stdio
transport's observed lifetime limit.

Local SDK builds use the canonical helper. Ordinary builds share the base's
mb2-managed `.default` working snapshot; custom repositories, packages and local
RPMs use isolated originals. `snapshot_key` explicitly isolates a project even
without custom inputs. Supply it when your project or machine policy requires
per-project isolation. `snapshot_repository` and `snapshot_package` use the same
helper options; repeat these inputs on later builds so outdated snapshots can
be restored. Only original targets go to mb2; working `.default` children are
managed by mb2. Bases remain free of project dependencies.

`sailfish_android_build` starts a remote Android/AppSupport build on the
configured build host. Configure `android_build_hosts.<host>.project_dir` or
pass `project_dir` to point at the remote Android source tree. The tool writes
job state under the remote `state_dir`, atomically creates a per-job directory,
and starts its own process group with `nohup` and `setsid`, so the SSH session
used to launch the job can disconnect without killing the build. Set
`build_timeout` for a remote build lifetime limit. Poll with
`sailfish_android_build_status`; omit `job_id` to list recent jobs, or pass a
job id and `wait_seconds` to wait mechanically for a state change. Running jobs
omit their log by default, while failed jobs include a bounded diagnostic
excerpt. Request bounded `lines` during scheduled progress checks; use
`verbose` only when full command/job inspection is needed.
Individual status waits are capped at 15 seconds. Use
`sailfish_android_build_cancel` to terminate the identity-checked process group.

`sailfish_sdk_refresh_metadata` starts a detached job to refresh zypper metadata in the installed SDK
exact requested target using the same privileged Docker wrapper as local builds.
`aarch64` refreshes the parent; `aarch64.default` or `aarch64-project` refreshes
that specific snapshot. No `.default` suffix is inferred. Use it when local SDK builds fail because a
package listed in repository metadata cannot be downloaded.

`sailfish_obs_results` and `sailfish_obs_buildlog` accept a friendly `server`
name configured in `paths.obs_servers`; each value is an `.oscrc` alias or API
URL passed to `osc -A`. Omit `server` to use `paths.osc_api_alias`. The advanced
`api_alias` argument accepts any raw `osc -A` alias or API URL and cannot be
combined with `server`. Keep machine- or organization-specific server mappings
in the local config rather than in the repository.

`sailfish_obs_results` can wait mechanically in intervals of at most 15 seconds
until OBS no longer reports an active state. `sailfish_obs_buildlog` returns a
bounded tail by default; set `verbose` only when the complete response is
required.

`sailfish_obs_buildlog` defaults to `osc api` with `nostream=1` so a build log
request does not become a long-running live stream. Set `nostream` to `false`
to use `osc remotebuildlog`.

Read-only tools include build preflight/status, the journal, topmost PID,
process maps, OBS lookup, repo search, spec summary, and QML checks.

## Smoke Test

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
  | /path/to/sailfish-devel-mcp/bin/sailfish-devel-mcp
```

## Development

Run tests without installing the package:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The canonical helper lives in the `build-sailfishos` skill. Update the exact
vendored copy with:

```sh
python3 scripts/update_build_helper.py /path/to/build-sailfishos/scripts/build_sailfishos.py
```

## Compact jobs and diagnostics

RPM installation and SDK metadata refresh now return detached build-job receipts
by default. Wait for `sailfish_build_status` to finish successfully before dependent
actions; `sailfish_build_cancel` cancels these jobs. Explicit `wait=true` retains
legacy synchronous behavior. For a multi-RPM transaction, timeout bounds the whole
async job; cancellation of local SSH does not guarantee rollback of a remote RPM
transaction. Inspect package state before retrying an interrupted install.

`sailfish_obs_watch` runs `osc results --watch --fail-on-error` in a detached job,
using the selected OBS alias and package filter. It does not modify OBS sources.

For long jobs, confirm detached startup and arrange a quiet scheduled follow-up
unless the user opts out, then return to the user. Each follow-up should inspect bounded progress evidence
and notify once on completion or failure. If scheduling is unavailable, report
that limitation. When the user explicitly requests waiting, use one CLI process
without repeated model-driven status calls:

```sh
bin/sailfish-devel-jobs wait --kind build --job-id JOB_ID
bin/sailfish-devel-jobs wait --kind device --job-id JOB_ID
bin/sailfish-devel-jobs wait --kind android --host HOST --job-id JOB_ID
bin/sailfish-devel-jobs status --kind build --job-id JOB_ID
bin/sailfish-devel-jobs log --kind build --job-id JOB_ID --offset 0 --max-bytes 6000
```

The waiter emits one JSON result at completion or failure. Exit codes are 0 for
success, 1 for failure/cancellation and 124 for wait expiration (which leaves the
job running). Installed packages expose `sailfish-devel-jobs` on PATH. Android
jobs accept an optional `--state-dir` matching their creation call.

Status results include a `revision`. Send `after_revision` on an occasional later
check to receive a minimal `unchanged` receipt when nothing changed. Explicit
`lines`, `verbose`, or `log_offset` requests still return their requested detail.
Build/device log pages are capped at 12,000 bytes and return `next_offset` and
`eof`. Tails are byte bounded too, including logs containing very long lines.
Verbose status retains full job metadata; compact completion exposes helper
version, backend, targets, duration, RPM paths, rpmlint and dependency diagnostics.

`sailfish_doctor` checks configured helper provenance, local executable availability,
SDK targets and configuration presence without contacting devices or OBS. It does
not prove Docker daemon access or network connectivity. The canonical helper also
provides `--doctor` and `--refresh-metadata --target TARGET [--force-refresh]`.

The QML checker lexes strings/comments and multiline ternaries. It reports missing
branch-local `//:` and `//%` comments; it is a focused checker, not a full QML parser.

## Maintaining the helper and skills

The vendored helper is pinned by `vendor/build-helper.json` with its version,
SHA-256 and available source revision/dirty state. Verify parity without editing:

```sh
python3 scripts/update_build_helper.py /path/to/build-sailfishos/scripts/build_sailfishos.py --check
```

The version check, CLI-control tests and snapshot tests guard the interface. Update
the canonical skill first, vendor it, and run both test suites before release.
`skills/sailfish-devel` is a separate optional skill for deployment, debugging,
Android and OBS workflows. Install/symlink that directory in your skill directory;
the canonical RPM skill stays focused on building and packaging.

### Detecting a stale host process

`sailfish_doctor` includes `host_runtime`: the PID, process start time (when
available), source-load time, and SHA-256 identities of package Python sources
at startup and currently on disk. `restart_needed: true` means the source tree
changed after startup; restart the MCP connection before relying on the updated
implementation. `null` means identity could not be checked. This is separate
from the existing canonical/vendored helper integrity check and does not restart
the server or interrupt jobs automatically.

### Build input provenance

Use `spec_path` in build/preflight requests to choose a repository's RPM spec,
for example `rpm/sensorfw-qt5.spec`. Ambiguous selection reports candidates.
Managed snapshots track dependency inputs, including local RPM hashes. Use
`reset_snapshot: true` when deliberately resetting a project's snapshot to
reapply changed inputs; SDK bases remain untouched. Build results include
`provenance` and `artifact_checksums` for tracing RPMs back to source and inputs.
After interrupted preparation, `resume_snapshot: true` explicitly retries the
identical recorded inputs without resetting an existing snapshot. Missing or
different recipes remain rejected. A build failure after preparation retains
the completed recipe, so it does not by itself require a reset.
