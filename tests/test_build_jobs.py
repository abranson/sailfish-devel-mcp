from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sailfish_devel_mcp.config import AndroidBuildHostConfig, Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.runner import CommandResult
from sailfish_devel_mcp import tools
from sailfish_devel_mcp.vendor import build_sailfishos


class BuildJobTests(unittest.TestCase):
    def make_config(self, root: Path) -> Config:
        return Config(
            path=None,
            default_device="test",
            devices={"test": DeviceConfig(name="test", ssh_target="root@test")},
            paths=PathConfig(
                git_root=root,
                obs_root=root / "OBS",
                ssh_config=root / "ssh_config",
                build_sailfishos=root / "build_sailfishos.py",
            ),
        )

    def wait_for_terminal(self, status_path: Path, timeout: float = 5.0) -> dict[str, object]:
        deadline = time.monotonic() + timeout
        status: dict[str, object] = {}
        while time.monotonic() < deadline:
            status = tools._read_job_status(status_path) or {}
            if tools._job_is_terminal(status):
                return status
            time.sleep(0.05)
        self.fail(f"job did not finish: {status}")

    def test_status_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.make_config(root)
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(root / "state")}):
                with self.assertRaisesRegex(ValueError, "unsupported characters"):
                    tools.handle_build_status(config, {"job_id": "../outside"})

    def test_status_uses_confined_log_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            job_dir = state / "builds" / "build-safe"
            job_dir.mkdir(parents=True)
            external = root / "secret.log"
            external.write_text("secret\n", encoding="utf-8")
            (job_dir / "build.log").write_text("safe\n", encoding="utf-8")
            tools._write_json_atomic(
                job_dir / "status.json",
                {
                    "job_id": "build-safe",
                    "state": "finished",
                    "returncode": 0,
                    "log_path": str(external),
                },
            )
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                response = tools.handle_build_status(
                    self.make_config(root),
                    {"job_id": "build-safe", "lines": 10},
                )

        text = response["content"][0]["text"]
        self.assertIn("safe", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("log_tail", response["structuredContent"])

    def test_failed_status_includes_bounded_excerpt_by_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            job_dir = state / "builds" / "build-failed"
            job_dir.mkdir(parents=True)
            (job_dir / "build.log").write_text(
                "ordinary output\nerror: concise failure\nlast line\n",
                encoding="utf-8",
            )
            tools._write_json_atomic(
                job_dir / "status.json",
                {
                    "job_id": "build-failed",
                    "state": "failed",
                    "returncode": 1,
                    "argv": ["python3", "very-long-command"],
                },
            )
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                response = tools.handle_build_status(
                    self.make_config(root),
                    {"job_id": "build-failed"},
                )

        self.assertIn("error: concise failure", response["content"][0]["text"])
        self.assertEqual(response["structuredContent"]["log_kind"], "failure_excerpt")
        self.assertNotIn("argv", response["structuredContent"])

    def test_atomic_status_writes_have_unique_temporaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda value: tools._write_json_atomic(path, {"value": value}), range(80)))
            payload = json.loads(path.read_text(encoding="utf-8"))
            leftovers = list(path.parent.glob(".status.json.*.tmp"))

        self.assertIn(payload["value"], range(80))
        self.assertEqual(leftovers, [])

    def test_background_job_records_metadata_and_finishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "last-build.json"
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(root / "state")}):
                job = tools._start_background_command(
                    "test build",
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).write_text(sys.argv[2])",
                        str(metadata),
                        json.dumps({"rpms": ["/tmp/example.rpm"]}),
                    ],
                    timeout=5,
                    metadata_path=metadata,
                )
                status = self.wait_for_terminal(Path(job["status_path"]))

        self.assertEqual(status["state"], "finished")
        self.assertEqual(status["returncode"], 0)
        self.assertEqual(status["artifacts"], ["/tmp/example.rpm"])

    def test_background_job_start_failure_becomes_terminal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metadata = root / "last-build.json"
            metadata.write_text(json.dumps({"rpms": ["/tmp/stale.rpm"]}), encoding="utf-8")
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(root / "state")}):
                job = tools._start_background_command(
                    "broken build",
                    [str(root / "does-not-exist")],
                    timeout=5,
                    metadata_path=metadata,
                )
                status = self.wait_for_terminal(Path(job["status_path"]))

        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["failure_class"], "supervisor")
        self.assertNotIn("artifacts", status)

    def test_job_list_reconciles_lost_supervisor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            job_dir = state / "builds" / "build-lost"
            job_dir.mkdir(parents=True)
            tools._write_json_atomic(
                job_dir / "status.json",
                {"job_id": "build-lost", "state": "running", "supervisor_pid": 99999999},
            )
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                response = tools.handle_build_status(self.make_config(root), {})

        self.assertEqual(response["structuredContent"]["jobs"][0]["state"], "failed")
        self.assertEqual(
            response["structuredContent"]["jobs"][0]["failure_class"],
            "supervisor-lost",
        )

    def test_background_job_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            config = self.make_config(root)
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                job = tools._start_background_command("slow build", ["/bin/sleep", "30"], timeout=60)
                status_path = Path(job["status_path"])
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status = tools._read_job_status(status_path) or {}
                    if status.get("state") == "running":
                        break
                    time.sleep(0.05)
                response = tools.handle_build_cancel(config, {"job_id": job["job_id"]})
                status = self.wait_for_terminal(status_path)

        self.assertFalse(response["isError"])
        self.assertEqual(status["state"], "cancelled")
        self.assertTrue(status["cancelled"])

    def test_device_command_job_has_separate_lifecycle_and_can_be_cancelled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            config = self.make_config(root)
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                job = tools._start_background_command(
                    "slow device command",
                    ["/bin/sh", "-c", "echo ready; sleep 30"],
                    timeout=60,
                    jobs_dir=tools._device_command_jobs_dir(),
                    job_prefix="device",
                    log_name="command.log",
                    status_fields={"job_kind": "device_command", "device": "test"},
                )
                status_path = Path(job["status_path"])
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    status = tools._read_job_status(status_path) or {}
                    if status.get("state") == "running":
                        break
                    time.sleep(0.05)
                running = tools.handle_device_command_status(
                    config,
                    {"job_id": job["job_id"]},
                )
                cancelled = tools.handle_device_command_cancel(
                    config,
                    {"job_id": job["job_id"]},
                )
                status = self.wait_for_terminal(status_path)

        self.assertIn("device-commands", job["status_path"])
        self.assertTrue(job["job_id"].startswith("device-"))
        self.assertEqual(running["structuredContent"]["log_kind"], "none")
        self.assertNotIn("argv", running["structuredContent"])
        self.assertFalse(cancelled["isError"])
        self.assertTrue(cancelled["structuredContent"]["cancel_requested"])
        self.assertEqual(status["state"], "cancelled")

    def test_device_command_failure_uses_confined_bounded_excerpt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            job_dir = state / "device-commands" / "device-failed"
            job_dir.mkdir(parents=True)
            external = root / "secret.log"
            external.write_text("secret\n", encoding="utf-8")
            (job_dir / "command.log").write_text(
                "ordinary output\nerror: useful device failure\nlast line\n",
                encoding="utf-8",
            )
            tools._write_json_atomic(
                job_dir / "status.json",
                {
                    "job_id": "device-failed",
                    "job_kind": "device_command",
                    "device": "test",
                    "state": "failed",
                    "returncode": 1,
                    "argv": ["ssh", "root@test", "secret-command"],
                    "log_path": str(external),
                },
            )
            with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)}):
                response = tools.handle_device_command_status(
                    self.make_config(root),
                    {"job_id": "device-failed"},
                )

        text = response["content"][0]["text"]
        structured = response["structuredContent"]
        self.assertTrue(response["isError"])
        self.assertIn("error: useful device failure", text)
        self.assertNotIn("secret", text)
        self.assertEqual(structured["log_kind"], "failure_excerpt")
        self.assertNotIn("argv", structured)

    def test_build_command_exposes_helper_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            command, project = tools._sailfish_build_command(
                self.make_config(root),
                {
                    "project_path": str(root),
                    "backend": "local",
                    "local_sdk": "/srv/mer/sdks/sfossdk/sdk-chroot",
                    "target": "aarch64-devel",
                    "pull_policy": "missing",
                    "no_vcs_apply": True,
                    "allow_untrusted_rpms": True,
                },
                dry_run=True,
            )

        self.assertEqual(project, root)
        self.assertIn("--backend", command)
        self.assertIn("/srv/mer/sdks/sfossdk/sdk-chroot", command)
        self.assertIn("aarch64-devel", command)
        self.assertIn("missing", command)
        self.assertIn("--no-vcs-apply", command)
        self.assertIn("--allow-untrusted-rpms", command)
        self.assertEqual(command[-2:], ["--dry-run", "--json"])

    def test_build_command_uses_quiet_output_for_real_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            command, _ = tools._sailfish_build_command(
                self.make_config(root),
                {"project_path": str(root), "backend": "local", "target": "aarch64"},
            )

        self.assertIn("--quiet", command)

    def test_local_build_command_forwards_stable_snapshot_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            command, _ = tools._sailfish_build_command(
                self.make_config(root),
                {
                    "project_path": str(root),
                    "backend": "local",
                    "snapshot_key": "browser-esr140",
                    "snapshot_repository": ["https://example.invalid/repo"],
                    "snapshot_package": ["qt5-qtdeclarative"],
                },
                dry_run=True,
            )

        self.assertIn("--snapshot-key", command)
        self.assertIn("browser-esr140", command)
        self.assertIn("--snapshot-repository", command)
        self.assertIn("https://example.invalid/repo", command)
        self.assertIn("--snapshot-package", command)
        self.assertIn("qt5-qtdeclarative", command)

    def test_snapshot_options_are_not_sent_to_docker_builds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "require the local backend"):
                tools._sailfish_build_command(
                    self.make_config(root),
                    {
                        "project_path": str(root),
                        "backend": "docker",
                        "snapshot_key": "browser-esr140",
                    },
                )

    def test_build_command_rejects_invalid_arch_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "arch must be"):
                tools._sailfish_build_command(
                    self.make_config(root),
                    {"project_path": str(root), "arch": ["aarch64", 7]},
                )

    def test_build_command_rejects_untrusted_local_sdk_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "under /srv/mer"):
                tools._sailfish_build_command(
                    self.make_config(root),
                    {
                        "project_path": str(root),
                        "backend": "local",
                        "local_sdk": "/etc/passwd",
                    },
                )

    def test_preflight_returns_parsed_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            (root / "build_sailfishos.py").write_text("# helper\n", encoding="utf-8")
            plan = {"backend": "docker", "mutates_project": False}
            result = CommandResult(("python3",), 0, json.dumps(plan), "")
            with patch("sailfish_devel_mcp.tools.run", return_value=result):
                response = tools.handle_build_preflight(
                    self.make_config(root),
                    {"project_path": str(root), "release": "5.0.0.43", "arch": "aarch64"},
                )

        self.assertFalse(response["isError"])
        self.assertEqual(response["structuredContent"]["plan"], plan)

    def test_android_job_scripts_are_atomic_and_identity_checked(self):
        host = AndroidBuildHostConfig(
            name="builder",
            ssh_target="builder@example",
            project_dir="/src/android",
            state_dir="/tmp/builds",
        )
        start = tools._android_build_start_command(
            host=host,
            project_dir=host.project_dir,
            state_dir=host.state_dir,
            job_id="android-test",
            shell="bash",
            shell_command="m services",
            build_timeout=3600,
        )
        cancel = tools._android_build_cancel_command(host.state_dir, "android-test")
        encoded = re.search(r" ([A-Za-z0-9+/=]+) \| base64 -d", start)
        self.assertIsNotNone(encoded)
        run_script = base64.b64decode(encoded.group(1)).decode("utf-8")

        self.assertIn('if ! mkdir "$job_dir"', start)
        self.assertNotIn('mkdir -p "$state_dir" "$job_dir"', start)
        self.assertIn("nohup setsid", start)
        self.assertIn("process_start", start)
        self.assertIn("build_timeout=3600", run_script)
        self.assertIn("android-build-watchdog", run_script)
        self.assertIn('kill -KILL -"$2"', run_script)
        self.assertIn("expected_start", cancel)
        self.assertIn('kill -TERM -"$pid"', cancel)

    def test_vendored_helper_has_versioned_interface(self):
        self.assertEqual(build_sailfishos.HELPER_VERSION, "2.4.4")
        args = build_sailfishos.parse_args(
            [
                "--backend",
                "local",
                "--snapshot-key",
                "browser-esr153",
                "--snapshot-repository",
                "browser=https://example.invalid/browser",
                "--snapshot-package",
                "qtmozembed-qt5-devel",
                "--pull-policy",
                "never",
                "--dry-run",
                "--json",
            ]
        )
        self.assertEqual(args.backend, "local")
        self.assertEqual(args.snapshot_key, "browser-esr153")
        self.assertEqual(args.snapshot_package, ["qtmozembed-qt5-devel"])
        self.assertEqual(args.pull_policy, "never")

    def test_android_timeout_terminates_remote_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            state = root / "state"
            project.mkdir()
            host = AndroidBuildHostConfig(
                name="local-test",
                ssh_target="unused",
                project_dir=str(project),
                state_dir=str(state),
            )
            start = tools._android_build_start_command(
                host=host,
                project_dir=str(project),
                state_dir=str(state),
                job_id="android-timeout",
                shell="sh",
                shell_command="sleep 30",
                build_timeout=1,
            )
            started = subprocess.run(["sh", "-c", start], check=False, capture_output=True, text=True)
            self.assertEqual(started.returncode, 0, started.stderr)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not (state / "android-timeout" / "timed_out").exists():
                time.sleep(0.05)
            timed_out = (state / "android-timeout" / "timed_out").exists()
            pid = int((state / "android-timeout" / "pid").read_text(encoding="utf-8"))
            expected_start = (state / "android-timeout" / "process_start").read_text(encoding="utf-8").strip()
            actual_start = tools._process_start_time(pid)
            while time.monotonic() < deadline and actual_start == expected_start:
                time.sleep(0.05)
                actual_start = tools._process_start_time(pid)

        self.assertTrue(timed_out)
        self.assertNotEqual(actual_start, expected_start)


if __name__ == "__main__":
    unittest.main()
