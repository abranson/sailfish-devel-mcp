from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import tools
from sailfish_devel_mcp.config import Config, DeviceConfig, PathConfig, load_config
from sailfish_devel_mcp.runner import scp_from_argv, scp_to_argv, ssh_argv


class PublicationFixTests(unittest.TestCase):
    def config(self, root):
        return Config(path=None, default_device="test",
                      devices={"test": DeviceConfig("test", "root@example.invalid")},
                      paths=PathConfig(git_root=root, obs_root=root))

    def test_fallback_search_does_not_follow_nested_symlinks(self):
        if not shutil.which("grep"):
            self.skipTest("grep unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "fixture").write_text("marker outside\n")
            (repo / "fixture").write_text("marker inside\n")
            (repo / "linked-directory").symlink_to(outside, target_is_directory=True)
            (repo / "linked-file").symlink_to(outside / "fixture")
            with patch.object(tools.shutil, "which", return_value=None):
                result = tools.handle_repo_find(self.config(repo), {"query": "marker"})
            text = result["content"][0]["text"]
            self.assertIn("marker inside", text)
            self.assertNotIn("marker outside", text)

    def test_discovered_specs_and_qml_reject_external_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            (repo / "rpm").mkdir(parents=True)
            external = root / "external"
            external.write_text("Name: outside\n")
            spec = repo / "rpm" / "linked.spec"
            spec.symlink_to(external)
            qml = repo / "linked.qml"
            qml.symlink_to(external)
            config = self.config(repo)
            with self.assertRaisesRegex(ValueError, "outside allowed roots"):
                tools.handle_spec_summary(config, {"repo_path": "."})
            with self.assertRaisesRegex(ValueError, "outside allowed roots"):
                tools.handle_qml_check_translator_ternaries(config, {"path": "."})
            # Internal symlinks remain usable.
            inside = repo / "inside"
            inside.write_text("Name: inside\n")
            spec.unlink()
            spec.symlink_to(inside)
            qml.unlink()
            qml.symlink_to(inside)
            result = tools.handle_spec_summary(config, {"repo_path": "."})
            self.assertEqual(result["structuredContent"]["summary"]["Name"], "inside")
            self.assertFalse(tools.handle_qml_check_translator_ternaries(config, {}).get("isError"))

    def test_discovered_spec_rejects_external_rpm_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (outside / "fixture.spec").write_text("Name: outside\n")
            (repo / "rpm").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "outside allowed roots"):
                tools.handle_spec_summary(self.config(repo), {})

    def test_default_ssh_config_without_user_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("sailfish_devel_mcp.config.Path.home", return_value=root), \
                    patch.dict(os.environ, {}, clear=True):
                config = load_config(root / "missing-config.json")
            self.assertEqual(config.paths.ssh_config, Path("/dev/null"))
            device = config.device()
            host = config.android_build_host()
            commands = [ssh_argv(device, config.paths.ssh_config, "true"),
                        scp_to_argv(device, config.paths.ssh_config, root / "file", "/tmp/file"),
                        scp_from_argv(device, config.paths.ssh_config, "/tmp/file", root / "file"),
                        tools._android_build_ssh_argv(config, host, "true")]
            for command in commands:
                self.assertEqual(command[1:3], ["-F", "/dev/null"])
            if shutil.which("ssh"):
                result = subprocess.run(["ssh", "-G", *commands[0][1:]],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_and_explicit_ssh_config_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            user_config = root / ".ssh" / "config"
            user_config.parent.mkdir()
            user_config.touch()
            with patch("sailfish_devel_mcp.config.Path.home", return_value=root), \
                    patch.dict(os.environ, {}, clear=True):
                config = load_config(root / "missing-config.json")
                self.assertEqual(config.paths.ssh_config, user_config)
                explicit = root / "explicit.json"
                explicit.write_text('{"paths":{"ssh_config":"/missing/explicit/config"}}')
                config = load_config(explicit)
                self.assertEqual(config.paths.ssh_config, Path("/missing/explicit/config"))

    def check_worker_termination(self, cancel):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker_pid_path = root / "worker.pid"
            worker = (
                "import os, signal, sys, time; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)"
            )
            leader = (
                "import subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
                "time.sleep(60)"
            )
            job = None
            worker_pid = None
            try:
                with patch.dict(os.environ, {"SAILFISH_DEVEL_MCP_STATE_DIR": str(root / "state")}):
                    job = tools._start_background_command(
                        "worker termination regression",
                        [sys.executable, "-c", leader, worker, str(worker_pid_path)],
                        timeout=50 if cancel else 2)
                    deadline = time.monotonic() + 5
                    while not worker_pid_path.exists() and time.monotonic() < deadline:
                        time.sleep(0.025)
                    self.assertTrue(worker_pid_path.exists())
                    worker_pid = int(worker_pid_path.read_text())
                    if cancel:
                        tools.handle_build_cancel(self.config(root), {"job_id": job["job_id"]})
                    deadline = time.monotonic() + 40
                    while time.monotonic() < deadline:
                        status = tools._read_job_status(Path(job["status_path"])) or {}
                        if tools._job_is_terminal(status):
                            break
                        time.sleep(0.05)
                    self.assertEqual(status.get("state"), "cancelled" if cancel else "timed_out")
                    try:
                        stat = Path(f"/proc/{worker_pid}/stat").read_text()
                    except FileNotFoundError:
                        pass
                    else:
                        self.assertIn(stat[stat.rfind(") ") + 2:].split()[0], {"Z", "X"})
            finally:
                if job:
                    status = tools._read_job_status(Path(job["status_path"])) or {}
                    if status.get("pid"):
                        try:
                            os.killpg(status["pid"], signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process = tools._BACKGROUND_SUPERVISORS.get(job["supervisor_pid"])
                    if process:
                        process.wait(timeout=5)

    def test_cancellation_reaps_term_ignoring_descendant(self):
        self.check_worker_termination(cancel=True)

    def test_timeout_reaps_term_ignoring_descendant(self):
        self.check_worker_termination(cancel=False)
