from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import tools
from sailfish_devel_mcp.config import AndroidBuildHostConfig, Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.prerequisites import probe_report, probe_script, probe_tools
from sailfish_devel_mcp.runner import CommandResult


def probe_output(features, missing=(), uid=0, session=True):
    lines = [f"uid\t{uid}", f"session_user\t{int(session)}",
             f"session_socket\t{int(session)}", "python3_compatible\t1"]
    lines += [f"tool:{tool}\t" + ("" if tool in missing else "/usr/bin/" + tool)
              for tool in probe_tools(features)]
    return "\n".join(lines) + "\n"


def probe_result(features, missing=(), uid=0):
    return CommandResult(("ssh",), 0, probe_output(features, missing, uid), "")


class PublicReleaseTests(unittest.TestCase):
    def config(self, root):
        return Config(path=None, default_device="phone",
                      devices={"phone": DeviceConfig("phone", "root@phone")},
                      paths=PathConfig(git_root=root, obs_root=root))

    def test_search_option_like_pattern_is_literal_with_both_backends(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.txt").write_text("value --files\n")
            config = self.config(root)
            if shutil.which("rg"):
                result = tools.handle_repo_find(config, {"query": "--files"})
                self.assertIn("fixture.txt:1:value --files", result["content"][0]["text"])
            if shutil.which("grep"):
                with patch.object(tools.shutil, "which", return_value=None):
                    result = tools.handle_repo_find(config, {"query": "--files"})
                self.assertIn("fixture.txt:1:value --files", result["content"][0]["text"])

    def test_fallback_search_honours_literal_patterns(self):
        if not shutil.which("grep"):
            self.skipTest("grep unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.txt").write_text("exact a.b\nother axb\n")
            with patch.object(tools.shutil, "which", return_value=None):
                result = tools.handle_repo_find(self.config(root), {"query": "a.b"})
            self.assertIn("exact a.b", result["content"][0]["text"])
            self.assertNotIn("other axb", result["content"][0]["text"])

    def test_unsafe_ssh_targets_rejected_for_devices_and_build_hosts(self):
        for target in ("-oProxyCommand=example@example.invalid", "root@host --flag",
                       "root@host\nnext", "root@host\t", "root@host\x00", "root@host\x7f"):
            with self.subTest(target=repr(target)), self.assertRaises(ValueError):
                DeviceConfig("phone", target)
            with self.subTest(target=repr(target)), self.assertRaises(ValueError):
                AndroidBuildHostConfig("builder", target, "/tree")
        config = self.config(Path("/tmp"))
        with patch.object(tools, "run") as run:
            with self.assertRaises(ValueError):
                tools.handle_device_journal(config, {"device": "-oProxyCommand=test@host"})
            with self.assertRaises(ValueError):
                tools.handle_android_build(config, {
                    "host": "-oProxyCommand=test@host", "shell_command": "true"})
        run.assert_not_called()

    def test_normal_ssh_targets_remain_supported(self):
        for target in ("phone", "root@phone", "user@example.invalid", "user@[::1]", "::1"):
            with self.subTest(target=target):
                self.assertEqual(DeviceConfig("phone", target).ssh_target, target)

    def test_commands_do_not_consume_mcp_stdin(self):
        script = """import sys
from sailfish_devel_mcp.runner import run
result = run([sys.executable, '-c', 'import sys; print(repr(sys.stdin.read()))'])
print(result.stdout.strip())
print(sys.stdin.read())
"""
        env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        process = subprocess.run([sys.executable, "-c", script], input="private MCP request",
                                 capture_output=True, text=True, env=env, timeout=5)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout, "''\nprivate MCP request\n")

    def test_setup_checks_only_by_default(self):
        with patch.object(tools, "_run_ssh", return_value=probe_result(["touch"], ["python3"])) as ssh, \
                patch.object(tools, "_start_operation") as start:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {"features": ["touch"]})
        self.assertFalse(result["isError"])
        self.assertFalse(result["structuredContent"]["ready"])
        self.assertEqual(result["structuredContent"]["installable_packages"], ["python3-base"])
        ssh.assert_called_once()
        start.assert_not_called()

    def test_setup_rejects_unknown_features_before_ssh(self):
        for features in ([], "touch", ["touch; install anything"], [1]):
            with self.subTest(features=features), patch.object(tools, "_run_ssh") as ssh:
                with self.assertRaises(ValueError):
                    tools.handle_device_setup(self.config(Path("/tmp")), {"features": features})
                ssh.assert_not_called()

    def test_setup_requires_root_for_installation(self):
        with patch.object(tools, "_run_ssh", return_value=probe_result(["touch"], ["python3"], uid=100000)), \
                patch.object(tools, "_start_operation") as start:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": ["touch"], "install_missing": True})
        self.assertTrue(result["isError"])
        self.assertIn("root SSH login", result["content"][0]["text"])
        start.assert_not_called()

    def test_setup_requires_package_manager(self):
        with patch.object(tools, "_run_ssh", return_value=probe_result(["touch"], ["python3", "pkcon", "zypper"])), \
                patch.object(tools, "_start_operation") as start:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": ["touch"], "install_missing": True})
        self.assertTrue(result["isError"])
        self.assertIn("pkcon or zypper", result["content"][0]["text"])
        start.assert_not_called()

    def test_base_os_tools_are_reported_for_manual_repair(self):
        with patch.object(tools, "_run_ssh", return_value=probe_result(["app_launch"], ["gio"])), \
                patch.object(tools, "_start_operation") as start:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": ["app_launch"], "install_missing": True})
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["manual_tools"], ["gio"])
        self.assertEqual(result["structuredContent"]["installable_packages"], [])
        start.assert_not_called()

    def test_setup_installs_only_supported_missing_packages_then_rechecks(self):
        features = ["touch", "input_trace"]
        with patch.object(tools, "_run_ssh", side_effect=[
            probe_result(features, ["python3", "evdev_trace"]),
            CommandResult(("ssh",), 0, "installed", ""), probe_result(features),
        ]) as ssh:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": features, "install_missing": True, "wait": True})
        self.assertEqual(ssh.call_args_list[1].args[2],
                         ["pkcon", "install", "-y", "mce-tools", "python3-base"])
        self.assertFalse(result["isError"])
        self.assertTrue(result["structuredContent"]["ready"])

    def test_setup_can_use_zypper_without_unsigned_or_repository_overrides(self):
        with patch.object(tools, "_run_ssh", side_effect=[
            probe_result(["touch"], ["python3", "pkcon"]),
            CommandResult(("ssh",), 0, "", ""), probe_result(["touch"]),
        ]) as ssh:
            tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": ["touch"], "install_missing": True, "wait": True})
        self.assertEqual(ssh.call_args_list[1].args[2],
                         ["zypper", "--non-interactive", "install", "--no-recommends", "python3-base"])

    def test_setup_preserves_install_failure_and_does_not_report_ready(self):
        with patch.object(tools, "_run_ssh", side_effect=[
            probe_result(["touch"], ["python3"]),
            CommandResult(("ssh",), 7, "", "repository failure"),
        ]) as ssh:
            result = tools.handle_device_setup(self.config(Path("/tmp")), {
                "features": ["touch"], "install_missing": True, "wait": True})
        self.assertTrue(result["isError"])
        self.assertEqual(ssh.call_count, 2)
        self.assertIn("repository failure", result["content"][0]["text"])

    def test_session_and_python_problems_require_manual_repair(self):
        report = probe_report(["touch"], probe_output(["touch"], session=False))
        self.assertTrue(report["ready"])
        report = probe_report(["app_launch"], probe_output(["app_launch"], session=False))
        self.assertFalse(report["ready"])
        self.assertEqual(len(report["session_issues"]), 2)
        report = probe_report(["touch"], probe_output(["touch"]).replace(
            "python3_compatible\t1", "python3_compatible\t0"))
        self.assertFalse(report["ready"])
        self.assertEqual(report["installable_packages"], [])
        self.assertIn("Python >=3.6", report["manual_tools"][0])

    def test_probe_keeps_configuration_out_of_shell_source(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "unexpected"
            hostile = "; touch " + str(marker)
            process = subprocess.run(["sh", "-c", probe_script(), "probe", hostile,
                                      "unix:path=" + hostile, "sh"],
                                     capture_output=True, text=True, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(marker.exists())
            self.assertIn("session_user\t0", process.stdout)

    def test_detached_setup_uses_jobs_cli_and_retains_final_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            marker = root / "installed"
            command_log = root / "transaction"
            script = "#!" + sys.executable + "\n" + f'''import pathlib, shlex, sys
marker = pathlib.Path({str(marker)!r})
command = shlex.split(sys.argv[-1])
if command[:2] == ['pkcon', 'install']:
    pathlib.Path({str(command_log)!r}).write_text(repr(command))
    marker.touch()
else:
    print({probe_output(['touch'], ['python3'])!r} if not marker.exists()
          else {probe_output(['touch'])!r}, end='')
'''
            (fake_bin / "ssh").write_text(script)
            (fake_bin / "ssh").chmod(0o755)
            env = {"SAILFISH_DEVEL_MCP_STATE_DIR": str(root / "state"),
                   "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
                   "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
            with patch.dict(os.environ, env):
                receipt = tools.handle_device_setup(self.config(root), {
                    "features": ["touch"], "install_missing": True})
                job_id = receipt["structuredContent"]["job_id"]
                process = subprocess.run([sys.executable, "-m", "sailfish_devel_mcp.jobs",
                                          "wait", "--job-id", job_id, "--timeout", "10",
                                          "--interval", "0.05"],
                                         capture_output=True, text=True, timeout=12)
                self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
                status = json.loads(process.stdout)["structuredContent"]
                self.assertEqual(status["state"], "finished")
                self.assertTrue(status["device_setup"]["ready"])
                result = json.loads(Path(status["result_path"]).read_text())
                self.assertTrue(result["structuredContent"]["ready"])
            self.assertEqual(command_log.read_text(), repr(["pkcon", "install", "-y", "python3-base"]))


if __name__ == "__main__":
    unittest.main()
