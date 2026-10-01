from __future__ import annotations

from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sailfish_devel_mcp.config import (
    AndroidBuildHostConfig,
    BUNDLED_BUILD_HELPER,
    Config,
    DEFAULT_ANDROID_BUILD_HOST,
    DEFAULT_ANDROID_BUILD_PROJECT_DIR,
    DEFAULT_ANDROID_BUILD_SSH_TARGET,
    DeviceConfig,
    PathConfig,
    USB_DEVICE_IP,
    load_config,
)
from sailfish_devel_mcp.runner import (
    IGNORED_HOST_KEY_OPTIONS,
    CommandResult,
    run,
    scp_from_argv,
    scp_to_argv,
    ssh_argv,
)
from sailfish_devel_mcp.server import McpServer, run_stdio
from sailfish_devel_mcp.tools import (
    MAX_MCP_WAIT_SECONDS,
    OBSERVED_MCP_TRANSPORT_LIFETIME_SECONDS,
    _device_home_path,
    _screenshot_prepare_command,
)
from sailfish_devel_mcp.vendor import build_sailfishos


class McpServerTests(unittest.TestCase):
    def test_bounded_wait_has_transport_safety_margin(self) -> None:
        self.assertLess(
            MAX_MCP_WAIT_SECONDS,
            OBSERVED_MCP_TRANSPORT_LIFETIME_SECONDS,
        )

    def make_server(self, root: Path) -> McpServer:
        config = Config(
            path=None,
            default_device="test",
            devices={"test": DeviceConfig(name="test", ssh_target="root@test")},
            paths=PathConfig(
                git_root=root,
                obs_root=root / "OBS",
                ssh_config=root / "ssh_config",
                build_sailfishos=root / "tools" / "build_sailfishos.py",
                osc_api_alias="primary-api",
                obs_servers={
                    "primary": "primary-api",
                    "secondary": "secondary-api",
                    "public": "public-api",
                },
            ),
        )
        return McpServer(config)

    def test_initialize_uses_requested_supported_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "test", "version": "0"},
                    },
                }
            )
        self.assertIsNotNone(response)
        self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")

    def test_tools_list_contains_device_and_qml_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            )
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("sailfish_device_topmost_pid", names)
        self.assertIn("sailfish_device_touch", names)
        self.assertIn("sailfish_device_touch_workflow", names)
        self.assertIn("sailfish_device_user_session_command", names)
        self.assertIn("sailfish_device_command_start", names)
        self.assertIn("sailfish_device_command_status", names)
        self.assertIn("sailfish_device_command_cancel", names)
        self.assertIn("sailfish_device_browser_launch", names)
        self.assertIn("sailfish_sdk_refresh_metadata", names)
        self.assertIn("sailfish_build_preflight", names)
        self.assertIn("sailfish_build_cancel", names)
        self.assertIn("sailfish_android_build_hosts", names)
        self.assertIn("sailfish_android_build", names)
        self.assertIn("sailfish_android_build_status", names)
        self.assertIn("sailfish_android_build_cancel", names)
        self.assertIn("sailfish_qml_check_translator_ternaries", names)
        obs_results = next(tool for tool in tools if tool["name"] == "sailfish_obs_results")
        server_schema = obs_results["inputSchema"]["properties"]["server"]
        self.assertNotIn("enum", server_schema)
        self.assertEqual(
            server_schema["description"],
            "Named OBS server configured in paths.obs_servers.",
        )
        synchronous = next(
            tool for tool in tools if tool["name"] == "sailfish_device_user_session_command"
        )
        self.assertEqual(
            synchronous["inputSchema"]["properties"]["timeout"]["maximum"],
            MAX_MCP_WAIT_SECONDS,
        )
        async_status = next(
            tool for tool in tools if tool["name"] == "sailfish_device_command_status"
        )
        self.assertEqual(
            async_status["inputSchema"]["properties"]["wait_seconds"]["maximum"],
            MAX_MCP_WAIT_SECONDS,
        )

    def test_initialize_directs_long_device_commands_to_async_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 20,
                    "method": "initialize",
                    "params": {},
                }
            )

        instructions = response["result"]["instructions"]
        self.assertLess(len(instructions), 100)
        self.assertIn("detached jobs", instructions)

    def test_device_command_status_rejects_transport_unsafe_wait(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 22,
                    "method": "tools/call",
                    "params": {
                        "name": "sailfish_device_command_status",
                        "arguments": {"wait_seconds": 21},
                    },
                }
            )

        self.assertTrue(response["result"]["isError"])
        self.assertIn(
            f"wait_seconds must be <= {MAX_MCP_WAIT_SECONDS}",
            response["result"]["content"][0]["text"],
        )

    def test_qml_ternary_checker_reports_inline_ternary_qstrid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            qml = root / "Example.qml"
            qml.write_text(
                'Text { text: enabled ? qsTrId("a") : qsTrId("b") }\n',
                encoding="utf-8",
            )
            server = self.make_server(root)
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "sailfish_qml_check_translator_ternaries",
                        "arguments": {"path": str(root)},
                    },
                }
            )
        self.assertTrue(response["result"]["isError"])
        findings = response["result"]["structuredContent"]["findings"]
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["line"], 1)

    def test_spec_summary_parses_core_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpm = root / "rpm"
            rpm.mkdir()
            spec = rpm / "sample.spec"
            spec.write_text(
                "\n".join(
                    [
                        "Name: sample",
                        "Version: 1.2.3",
                        "Release: 1",
                        "Summary: Sample package",
                        "BuildRequires: pkgconfig(Qt5Core)",
                        "Requires: lipstick",
                    ]
                ),
                encoding="utf-8",
            )
            server = self.make_server(root)
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "sailfish_spec_summary",
                        "arguments": {"repo_path": str(root)},
                    },
                }
            )
        summary = response["result"]["structuredContent"]["summary"]
        self.assertEqual(summary["Name"], "sample")
        self.assertEqual(summary["Version"], "1.2.3")
        self.assertEqual(summary["BuildRequires"], ["pkgconfig(Qt5Core)"])

    def test_server_writes_json_serializable_tool_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "sailfish_devices", "arguments": {}},
                }
            )
        json.dumps(response)

    def test_timeout_output_bytes_are_normalized_to_text(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=("ssh", "root@test"),
            timeout=1,
            output=b"partial stdout\n",
            stderr=b"partial stderr\xff\n",
        )
        with patch("sailfish_devel_mcp.runner.subprocess.run", side_effect=timeout):
            result = run(["ssh", "root@test"], timeout=1)

        self.assertEqual(result.returncode, 124)
        self.assertIsInstance(result.stdout, str)
        self.assertIsInstance(result.stderr, str)
        self.assertIn("partial stdout", result.stdout)
        self.assertIn("partial stderr", result.stderr)
        self.assertIn("command timed out after 1s", result.stderr)
        json.dumps(result.public_dict())

    def test_user_session_command_is_compact_unless_verbose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            output = "x" * 10000
            with patch("sailfish_devel_mcp.tools._run_ssh") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh", "large-command"), 0, output, "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 50,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_user_session_command",
                            "arguments": {"command": ["example"]},
                        },
                    }
                )
                verbose = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 51,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_user_session_command",
                            "arguments": {"command": ["example"], "verbose": True},
                        },
                    }
                )

        compact = response["result"]["structuredContent"]
        self.assertNotIn("argv", compact)
        self.assertNotIn("stdout", compact)
        self.assertEqual(compact["stdout_chars"], len(output))
        self.assertIn("argv", verbose["result"]["structuredContent"])
        self.assertIn("stdout", verbose["result"]["structuredContent"])

    def test_user_session_command_timeout_returns_error_and_server_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools._run_ssh") as mocked_run:
                mocked_run.return_value = CommandResult(
                    ("ssh", "root@test"),
                    124,
                    "",
                    f"command timed out after {MAX_MCP_WAIT_SECONDS}s",
                )
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 52,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_user_session_command",
                            "arguments": {"command": ["slow-command"]},
                        },
                    }
                )
            follow_up = server.handle(
                {"jsonrpc": "2.0", "id": 53, "method": "tools/list", "params": {}}
            )

        self.assertTrue(response["result"]["isError"])
        self.assertEqual(response["result"]["structuredContent"]["returncode"], 124)
        self.assertIn("timed out", response["result"]["content"][0]["text"])
        self.assertIn("tools", follow_up["result"])

    def test_tool_exception_returns_tool_error_and_server_recovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch(
                "sailfish_devel_mcp.tools.handle_devices",
                side_effect=RuntimeError("boom"),
            ):
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {"name": "sailfish_devices", "arguments": {}},
                    }
                )
            follow_up = server.handle(
                {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
            )

        self.assertNotIn("error", response)
        self.assertTrue(response["result"]["isError"])
        self.assertEqual(
            response["result"]["structuredContent"]["exception"],
            "RuntimeError",
        )
        self.assertIn("tools", follow_up["result"])

    def test_stdio_serialization_failure_does_not_stop_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            stdin = StringIO(
                "\n".join(
                    [
                        '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}',
                        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}',
                    ]
                )
                + "\n"
            )
            stdout = StringIO()
            with patch.object(
                server,
                "handle",
                side_effect=[
                    {"jsonrpc": "2.0", "id": 1, "result": {"bad": {1}}},
                    {"jsonrpc": "2.0", "id": 2, "result": {"ok": True}},
                ],
            ):
                run_stdio(server, stdin, stdout)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(responses[0]["id"], 1)
        self.assertEqual(responses[0]["error"]["code"], -32603)
        self.assertIn("response serialization failed", responses[0]["error"]["message"])
        self.assertEqual(responses[1]["result"], {"ok": True})

    def test_default_config_uses_bundled_build_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing-config.json"
            with patch.dict(os.environ, {}, clear=True):
                config = load_config(missing)
        self.assertEqual(config.default_device, "device")
        self.assertEqual(config.devices["device"].ssh_target, "root@device")
        self.assertEqual(config.devices["device"].username, "defaultuser")
        self.assertEqual(_device_home_path(config.devices["device"]), "/home/defaultuser")
        self.assertNotIn("ssh_config", config.devices["device"].public_dict())
        self.assertEqual(config.paths.obs_root, Path.home() / "OBS")
        self.assertEqual(config.paths.build_sailfishos, BUNDLED_BUILD_HELPER)
        self.assertIsNone(config.paths.local_sdk)
        self.assertTrue(config.paths.build_sailfishos.exists())
        self.assertNotIn("build-sailfishos-skill", str(config.paths.build_sailfishos))
        self.assertEqual(config.default_android_build_host, DEFAULT_ANDROID_BUILD_HOST)
        self.assertEqual(
            config.android_build_hosts[DEFAULT_ANDROID_BUILD_HOST].ssh_target,
            DEFAULT_ANDROID_BUILD_SSH_TARGET,
        )
        self.assertEqual(
            config.android_build_hosts[DEFAULT_ANDROID_BUILD_HOST].project_dir,
            DEFAULT_ANDROID_BUILD_PROJECT_DIR,
        )

    def test_usb_device_uses_fixed_address_without_dns(self) -> None:
        config = Config(
            path=None,
            default_device="phone",
            devices={
                "phone": DeviceConfig(
                    name="phone",
                    ssh_target="root@phone",
                    username="nemo",
                    architecture="aarch64",
                )
            },
        )

        for name in ("usb", "usb:phone"):
            with self.subTest(name=name):
                device = config.device(name)
                self.assertEqual(device.name, "phone")
                self.assertEqual(device.ssh_target, f"root@{USB_DEVICE_IP}")
                self.assertEqual(device.username, "nemo")
                self.assertEqual(device.architecture, "aarch64")
                self.assertTrue(device.ignore_ssh_host_keys)

        with self.assertRaisesRegex(KeyError, "unknown Sailfish device: missing"):
            config.device("usb:missing")

    def test_usb_device_ssh_and_scp_ignore_host_keys(self) -> None:
        device = DeviceConfig(
            name="phone",
            ssh_target=f"root@{USB_DEVICE_IP}",
            ignore_ssh_host_keys=True,
        )
        ssh_config = Path("/tmp/ssh-config")
        local_path = Path("/tmp/package.rpm")

        commands = (
            ssh_argv(device, ssh_config, "true"),
            scp_to_argv(device, ssh_config, local_path, "/tmp/package.rpm"),
            scp_from_argv(
                device,
                ssh_config,
                "/tmp/screenshot.png",
                Path("/tmp/screenshot.png"),
            ),
        )
        for argv in commands:
            with self.subTest(command=argv[0]):
                self.assertEqual(argv[1:3], ["-F", str(ssh_config)])
                options_end = 3 + len(IGNORED_HOST_KEY_OPTIONS)
                self.assertEqual(argv[3:options_end], IGNORED_HOST_KEY_OPTIONS)

    def test_usb_tool_argument_uses_fixed_address_and_host_key_options(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh",), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 15,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_journal",
                            "arguments": {"device": "usb:test"},
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        mocked_run.assert_called_once()
        argv = list(mocked_run.call_args.args[0])
        self.assertIn(f"root@{USB_DEVICE_IP}", argv)
        options_end = 3 + len(IGNORED_HOST_KEY_OPTIONS)
        self.assertEqual(argv[3:options_end], IGNORED_HOST_KEY_OPTIONS)

    def test_config_template_contains_only_generic_build_host_defaults(self) -> None:
        template = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "sailfish_devel_mcp"
            / "config.py"
        ).read_text(encoding="utf-8")
        self.assertIn('DEFAULT_ANDROID_BUILD_HOST = "android-builder"', template)
        self.assertIn(
            'DEFAULT_ANDROID_BUILD_SSH_TARGET = "builder@example.invalid"',
            template,
        )

    def test_config_loads_local_sdk_from_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_sdk = root / "sdk-chroot"
            obs_root = root / "OBS"
            ssh_config = root / "ssh_config"
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "devices": {"phone": "root@phone"},
                        "paths": {
                            "git_root": str(root),
                            "obs_root": str(obs_root),
                            "ssh_config": str(ssh_config),
                            "local_sdk": str(local_sdk),
                            "obs_servers": {
                                "primary": "private-api",
                                "community": "public-api",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(config_path)
        self.assertEqual(config.paths.local_sdk, local_sdk)
        self.assertEqual(config.paths.obs_root, obs_root)
        self.assertEqual(config.paths.ssh_config, ssh_config)
        self.assertEqual(
            config.paths.obs_servers,
            {"primary": "private-api", "community": "public-api"},
        )
        self.assertEqual(config.devices["phone"].release, "")

    def test_config_rejects_invalid_obs_servers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            for obs_servers in ([], {"primary": ""}, {"primary": 7}):
                with self.subTest(obs_servers=obs_servers):
                    config_path.write_text(
                        json.dumps({"paths": {"obs_servers": obs_servers}}),
                        encoding="utf-8",
                    )
                    with self.assertRaises(ValueError):
                        load_config(config_path)

    def test_config_keeps_device_release_literal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "devices": {
                            "phone": {
                                "ssh_target": "root@phone",
                                "release": "devel",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            config = load_config(config_path)
        self.assertEqual(config.devices["phone"].release, "devel")

    def test_repo_find_allows_obs_root_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            obs_checkout = root / "OBS" / "home:example" / "browser"
            obs_checkout.mkdir(parents=True)
            server = self.make_server(root)
            with (
                patch("sailfish_devel_mcp.tools.shutil.which", return_value="/usr/bin/rg"),
                patch("sailfish_devel_mcp.tools.run") as mocked_run,
            ):
                mocked_run.return_value = CommandResult(("rg",), 0, "match\n", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_repo_find",
                            "arguments": {
                                "path": str(obs_checkout),
                                "query": "Package",
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_run.call_args.args[0])
        self.assertEqual(argv[-1], str(obs_checkout))

    def test_screenshot_prepare_command_uses_home_ownership(self) -> None:
        device = DeviceConfig(name="test", ssh_target="root@test")
        command = _screenshot_prepare_command(
            device,
            "/home/defaultuser/Pictures/Screenshots/example.png",
        )
        self.assertIn("stat -Lc %U", command)
        self.assertIn("install -d -m 775", command)
        self.assertIn("install -d -m 755", command)
        self.assertIn("privileged", command)

    def test_device_touch_tap_builds_input_injection_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(
                    ("ssh", "root@test"),
                    0,
                    "input_device=/dev/input/event5\ntap=ok\n",
                    "",
                )
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_touch",
                            "arguments": {
                                "action": "tap",
                                "input_device": "/dev/input/event5",
                                "x": 12,
                                "y": 34,
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = mocked_run.call_args.args[0]
        remote = argv[-1]
        self.assertEqual(argv[:3], ["ssh", "-F", str(Path(tmp) / "ssh_config")])
        self.assertIn("INPUT_DEVICE=/dev/input/event5", remote)
        self.assertIn("X=12", remote)
        self.assertIn("Y=34", remote)
        self.assertIn("ABS_MT_TRACKING_ID", remote)

    def test_device_touch_discover_uses_evdev_trace_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh", "root@test"), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 7,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_touch",
                            "arguments": {"action": "discover"},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        remote = mocked_run.call_args.args[0][-1]
        self.assertNotIn("evdev_trace -i", remote)
        self.assertIn("/proc/bus/input/devices", remote)

    def test_device_touch_discover_can_include_evdev_trace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh", "root@test"), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 8,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_touch",
                            "arguments": {
                                "action": "discover",
                                "include_evdev_trace": True,
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        remote = mocked_run.call_args.args[0][-1]
        self.assertIn("evdev_trace -i", remote)

    def test_device_touch_workflow_screenshots_discovers_and_taps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.side_effect = [
                    CommandResult(("ssh", "root@test"), 0, "screenshot\n", ""),
                    CommandResult(("ssh", "root@test"), 0, "inputs\n", ""),
                    CommandResult(("ssh", "root@test"), 0, "tap=ok\n", ""),
                ]
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 9,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_touch_workflow",
                            "arguments": {"action": "tap", "x": 12, "y": 34},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        self.assertEqual(
            response["result"]["structuredContent"]["step_order"],
            ["screenshot_before", "touchscreen_discovery", "touch"],
        )
        remotes = [call.args[0][-1] for call in mocked_run.call_args_list]
        self.assertIn("saveScreenshot", remotes[0])
        self.assertIn("/proc/bus/input/devices", remotes[1])
        self.assertIn("X=12", remotes[2])
        self.assertIn("Y=34", remotes[2])

    def test_user_session_command_can_run_as_defaultuser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh", "root@test"), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 10,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_user_session_command",
                            "arguments": {
                                "command": ["systemctl", "--user", "status", "app.service"],
                                "run_as_user": True,
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        remote = mocked_run.call_args.args[0][-1]
        self.assertIn("runuser -u defaultuser -- env", remote)
        self.assertIn("XDG_RUNTIME_DIR=/run/user/100000", remote)
        self.assertIn("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/100000/dbus/user_bus_socket", remote)
        self.assertIn("systemctl --user status app.service", remote)

    def test_device_command_start_detaches_user_session_ssh_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            server = self.make_server(root)
            with (
                patch.dict(
                    os.environ,
                    {"SAILFISH_DEVEL_MCP_STATE_DIR": str(state)},
                ),
                patch("sailfish_devel_mcp.tools._start_background_command") as mocked_start,
            ):
                mocked_start.return_value = {
                    "job_id": "device-test",
                    "state": "starting",
                    "status_path": str(state / "status.json"),
                    "log_path": str(state / "command.log"),
                }
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 21,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_command_start",
                            "arguments": {
                                "command": ["gdb", "--batch", "/usr/bin/example"],
                                "run_as_user": True,
                                "timeout": 7200,
                            },
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        self.assertEqual(response["result"]["structuredContent"]["job_id"], "device-test")
        label, argv = mocked_start.call_args.args
        options = mocked_start.call_args.kwargs
        self.assertEqual(label, "device command on test")
        self.assertEqual(argv[:3], ["ssh", "-F", str(root / "ssh_config")])
        self.assertEqual(argv[3:5], ["--", "root@test"])
        self.assertIn("runuser -u defaultuser", argv[-1])
        self.assertIn("gdb --batch /usr/bin/example", argv[-1])
        self.assertEqual(options["timeout"], 7200)
        self.assertEqual(options["jobs_dir"], state / "device-commands")
        self.assertEqual(options["job_prefix"], "device")
        self.assertEqual(options["log_name"], "command.log")

    def test_device_install_rpm_keeps_single_remote_path_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpm = root / "sample.rpm"
            rpm.write_text("rpm", encoding="utf-8")
            server = self.make_server(root)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.side_effect = [
                    CommandResult(("scp",), 0, "", ""),
                    CommandResult(("ssh",), 0, "installed\n", ""),
                ]
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 18,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_install_rpm",
                            "arguments": {"wait": True,
                                "rpm_path": str(rpm),
                                "remote_path": "/tmp/custom.rpm",
                            },
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        calls = [list(call.args[0]) for call in mocked_run.call_args_list]
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][-1], "root@test:/tmp/custom.rpm")
        self.assertEqual(calls[1][-1], "pkcon install-local -y /tmp/custom.rpm")
        self.assertEqual(
            response["result"]["structuredContent"]["remote_paths"],
            ["/tmp/custom.rpm"],
        )

    def test_device_install_rpm_installs_multiple_rpms_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpm_a = root / "sample.rpm"
            rpm_b = root / "sample-deps.rpm"
            rpm_a.write_text("rpm", encoding="utf-8")
            rpm_b.write_text("rpm", encoding="utf-8")
            server = self.make_server(root)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.side_effect = [
                    CommandResult(("ssh",), 0, "", ""),
                    CommandResult(("scp",), 0, "", ""),
                    CommandResult(("scp",), 0, "", ""),
                    CommandResult(("ssh",), 0, "installed\n", ""),
                ]
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 19,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_install_rpm",
                            "arguments": {"wait": True,
                                "rpm_paths": [str(rpm_a), str(rpm_b)],
                                "remote_dir": "/tmp/test-rpms",
                                "installer": "rpm",
                            },
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        calls = [list(call.args[0]) for call in mocked_run.call_args_list]
        self.assertEqual(calls[0][-1], "mkdir -p /tmp/test-rpms")
        self.assertEqual(calls[1][-1], "root@test:/tmp/test-rpms/sample.rpm")
        self.assertEqual(calls[2][-1], "root@test:/tmp/test-rpms/sample-deps.rpm")
        self.assertEqual(
            calls[3][-1],
            "rpm -Uvh --replacepkgs /tmp/test-rpms/sample.rpm /tmp/test-rpms/sample-deps.rpm",
        )
        self.assertEqual(
            response["result"]["structuredContent"]["remote_paths"],
            ["/tmp/test-rpms/sample.rpm", "/tmp/test-rpms/sample-deps.rpm"],
        )

    def test_browser_launch_uses_display_env_and_reports_topmost_pid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("ssh", "root@test"), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 11,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_device_browser_launch",
                            "arguments": {"url": "https://example.com"},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        remote = mocked_run.call_args.args[0][-1]
        self.assertIn("WAYLAND_DISPLAY=../../display/wayland-0", remote)
        self.assertIn("/usr/bin/invoker --type=browser,silica-qt5 -A --", remote)
        self.assertIn("/usr/bin/sailfish-browser https://example.com", remote)
        self.assertIn("privateTopmostWindowProcessId", remote)

    def test_obs_buildlog_uses_nostream_api_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("osc",), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 12,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_obs_buildlog",
                            "arguments": {
                                "project": "home:example",
                                "package": "browser",
                                "repository": "5.0.0",
                                "arch": "aarch64",
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_run.call_args.args[0])
        self.assertEqual(argv[:3], ["osc", "-A", "primary-api"])
        self.assertEqual(argv[3], "api")
        self.assertEqual(
            argv[4],
            "/build/home%3Aexample/5.0.0/aarch64/browser/_log?nostream=1",
        )

    def test_obs_results_selects_named_servers(self) -> None:
        aliases = {
            "primary": "primary-api",
            "secondary": "secondary-api",
            "public": "public-api",
        }
        with tempfile.TemporaryDirectory() as tmp:
            mcp_server = self.make_server(Path(tmp))
            for named_server, api_alias in aliases.items():
                with self.subTest(server=named_server):
                    with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                        mocked_run.return_value = CommandResult(("osc",), 0, "", "")
                        response = mcp_server.handle(
                            {
                                "jsonrpc": "2.0",
                                "id": 13,
                                "method": "tools/call",
                                "params": {
                                    "name": "sailfish_obs_results",
                                    "arguments": {
                                        "project": "home:example",
                                        "package": "browser",
                                        "server": named_server,
                                    },
                                },
                            }
                        )

                    self.assertFalse(response["result"].get("isError", False))
                    argv = list(mocked_run.call_args.args[0])
                    self.assertEqual(
                        argv,
                        [
                            "osc",
                            "-A",
                            api_alias,
                            "results",
                            "home:example",
                            "browser",
                        ],
                    )
                    structured = response["result"]["structuredContent"]
                    self.assertEqual(structured["server"], named_server)
                    self.assertEqual(structured["api_alias"], api_alias)

    def test_obs_results_waits_mechanically_until_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with (
                patch("sailfish_devel_mcp.tools.run") as mocked_run,
                patch("sailfish_devel_mcp.tools.time.sleep"),
            ):
                mocked_run.side_effect = [
                    CommandResult(("osc",), 0, "repo aarch64 building", ""),
                    CommandResult(("osc",), 0, "repo aarch64 succeeded", ""),
                ]
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 52,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_obs_results",
                            "arguments": {
                                "project": "home:example",
                                "package": "browser",
                                "wait_seconds": 10,
                                "poll_interval": 1,
                            },
                        },
                    }
                )

        structured = response["result"]["structuredContent"]
        self.assertEqual(mocked_run.call_count, 2)
        self.assertEqual(structured["polls"], 2)
        self.assertFalse(structured["pending"])
        self.assertFalse(structured["wait_expired"])

    def test_obs_results_rejects_server_with_api_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_obs_results",
                            "arguments": {
                                "project": "home:example",
                                "server": "secondary",
                                "api_alias": "public-api",
                            },
                        },
                    }
                )

        self.assertTrue(response["result"].get("isError", False))
        self.assertIn(
            "server and api_alias cannot be combined",
            response["result"]["content"][0]["text"],
        )
        mocked_run.assert_not_called()

    def test_obs_results_rejects_unconfigured_named_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 15,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_obs_results",
                            "arguments": {
                                "project": "home:example",
                                "server": "unknown",
                            },
                        },
                    }
                )

        self.assertTrue(response["result"].get("isError", False))
        self.assertIn(
            "server must be one of: primary, secondary, public",
            response["result"]["content"][0]["text"],
        )
        mocked_run.assert_not_called()

    def test_sdk_refresh_metadata_uses_local_sdk_main_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_sdk = root / "sdks" / "sfossdk" / "sdk-chroot"
            local_sdk.parent.mkdir(parents=True)
            local_sdk.touch()
            self.write_fake_target(
                local_sdk.parent,
                "aarch64",
                ssu_release="live",
                version_id="5.2.0.4",
            )
            config = Config(
                path=None,
                default_device="phone",
                devices={
                    "phone": DeviceConfig(
                        name="phone",
                        ssh_target="root@phone",
                        architecture="aarch64",
                        release="live",
                    )
                },
                paths=PathConfig(
                    git_root=root,
                    ssh_config=root / "ssh_config",
                    local_sdk=local_sdk,
                ),
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("docker",), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 13,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_sdk_refresh_metadata",
                            "arguments": {"wait": True,"device": "phone"},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_run.call_args.args[0])
        self.assertEqual(argv[:3], ["docker", "run", "--rm"])
        wrapper = argv[-1]
        self.assertIn("sb2 -t aarch64.default -m sdk-install -R zypper ref", wrapper)
        self.assertEqual(
            response["result"]["structuredContent"]["main_target"],
            "aarch64.default",
        )

    def test_sdk_refresh_metadata_uses_project_snapshot_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_sdk = root / "sdks" / "sfossdk" / "sdk-chroot"
            local_sdk.parent.mkdir(parents=True)
            local_sdk.touch()
            target = "aarch64-browser-esr153"
            self.write_fake_target(
                local_sdk.parent,
                target,
                ssu_release="live",
                version_id="5.2.0.4",
            )
            (local_sdk.parent / "targets" / target / ".sdk-manage.conf").write_text(
                "snapshot-of=aarch64\n",
                encoding="utf-8",
            )
            config = Config(
                path=None,
                default_device=None,
                devices={},
                paths=PathConfig(
                    git_root=root,
                    local_sdk=local_sdk,
                ),
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("docker",), 0, "", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_sdk_refresh_metadata",
                            "arguments": {"wait": True, "target": target},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_run.call_args.args[0])
        wrapper = argv[-1]
        self.assertIn(
            f"sb2 -t {target} -m sdk-install -R zypper ref",
            wrapper,
        )
        self.assertNotIn(f"{target}.default", wrapper)
        self.assertEqual(
            response["result"]["structuredContent"]["main_target"],
            target,
        )

    def test_build_defaults_prefer_configured_local_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            helper = root / "build_sailfishos.py"
            local_sdk = root / "sdk-chroot"
            helper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            config = Config(
                path=None,
                default_device="phone",
                devices={
                    "phone": DeviceConfig(
                        name="phone",
                        ssh_target="root@phone",
                        architecture="aarch64",
                        release="live",
                    )
                },
                paths=PathConfig(
                    git_root=root,
                    ssh_config=root / "ssh_config",
                    build_sailfishos=helper,
                    local_sdk=local_sdk,
                ),
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools._start_background_command") as mocked_start:
                mocked_start.return_value = {
                    "job_id": "build-test",
                    "status_path": str(root / "status.json"),
                    "log_path": str(root / "build.log"),
                }
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 6,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_build_rpm",
                            "arguments": {"project_path": str(root), "device": "phone"},
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_start.call_args.args[1])
        self.assertIn("--local-sdk", argv)
        self.assertIn(str(local_sdk), argv)
        self.assertIn("--release", argv)
        self.assertIn("live", argv)
        self.assertIn("--arch", argv)
        self.assertIn("aarch64", argv)
        self.assertEqual(
            response["result"]["structuredContent"]["job_id"],
            "build-test",
        )

    def test_build_without_release_defaults_to_live_local_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            helper = root / "build_sailfishos.py"
            local_sdk = root / "sdk-chroot"
            helper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            config = Config(
                path=None,
                default_device="phone",
                devices={"phone": DeviceConfig(name="phone", ssh_target="root@phone")},
                paths=PathConfig(
                    git_root=root,
                    ssh_config=root / "ssh_config",
                    build_sailfishos=helper,
                    local_sdk=local_sdk,
                ),
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools._start_background_command") as mocked_start:
                mocked_start.return_value = {
                    "job_id": "build-test",
                    "status_path": str(root / "status.json"),
                    "log_path": str(root / "build.log"),
                }
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 14,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_build_rpm",
                            "arguments": {
                                "project_path": str(root),
                                "arch": "aarch64",
                            },
                        },
                    }
                )
        self.assertFalse(response["result"].get("isError", False))
        argv = list(mocked_start.call_args.args[1])
        self.assertIn("--local-sdk", argv)
        self.assertIn(str(local_sdk), argv)
        self.assertIn("--release", argv)
        self.assertIn("live", argv)
        self.assertIn("--arch", argv)
        self.assertIn("aarch64", argv)

    def test_build_wait_true_uses_synchronous_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            helper = root / "build_sailfishos.py"
            helper.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            config = Config(
                path=None,
                default_device="phone",
                devices={"phone": DeviceConfig(name="phone", ssh_target="root@phone")},
                paths=PathConfig(
                    git_root=root,
                    ssh_config=root / "ssh_config",
                    build_sailfishos=helper,
                ),
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(("python3", str(helper)), 0, "ok", "")
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 15,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_build_rpm",
                            "arguments": {
                                "project_path": str(root),
                                "arch": "aarch64",
                                "wait": True,
                            },
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        self.assertEqual(response["result"]["structuredContent"]["returncode"], 0)
        argv = list(mocked_run.call_args.args[0])
        self.assertIn("--arch", argv)
        self.assertIn("aarch64", argv)

    def test_android_build_starts_remote_nohup_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = Config(
                path=None,
                default_device="phone",
                devices={"phone": DeviceConfig(name="phone", ssh_target="root@phone")},
                paths=PathConfig(git_root=root, ssh_config=root / "ssh_config"),
                default_android_build_host="android-builder",
                android_build_hosts={
                    "android-builder": AndroidBuildHostConfig(
                        name="android-builder",
                        ssh_target="builder@example.invalid",
                        project_dir="/remote/a15",
                        state_dir="/remote/state/android-builds",
                    )
                },
            )
            server = McpServer(config)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(
                    ("ssh",),
                    0,
                    "job_id: android-test\npid: 1234\n",
                    "",
                )
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 16,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_android_build",
                            "arguments": {
                                "job_id": "android-test",
                                "shell_command": "source build/envsetup.sh && m services",
                            },
                        },
                    }
                )

        self.assertFalse(response["result"].get("isError", False))
        self.assertEqual(
            response["result"]["structuredContent"]["job_id"],
            "android-test",
        )
        argv = list(mocked_run.call_args.args[0])
        self.assertEqual(argv[:3], ["ssh", "-F", str(root / "ssh_config")])
        self.assertIn("builder@example.invalid", argv)
        remote = argv[-1]
        self.assertIn("nohup", remote)
        self.assertIn("/remote/a15", remote)
        self.assertIn("/remote/state/android-builds/android-test", remote)
        self.assertIn("base64 -d", remote)

    def test_android_build_requires_configured_project_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 16,
                    "method": "tools/call",
                    "params": {
                        "name": "sailfish_android_build",
                        "arguments": {
                            "job_id": "android-test",
                            "shell_command": "source build/envsetup.sh && m services",
                        },
                    },
                }
            )

        self.assertTrue(response["result"].get("isError", False))
        self.assertIn(
            "project_dir is required",
            response["result"]["content"][0]["text"],
        )

    def test_android_build_status_tails_remote_job_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = self.make_server(root)
            with patch("sailfish_devel_mcp.tools.run") as mocked_run:
                mocked_run.return_value = CommandResult(
                    ("ssh",),
                    0,
                    "\n".join(
                        [
                            "job_id: android-test",
                            "state: finished",
                            "returncode: 7",
                            "pid: 1234",
                            "log_path: /remote/state/android-test/build.log",
                            "",
                            "build failed",
                        ]
                    ),
                    "",
                )
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 17,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_android_build_status",
                            "arguments": {
                                "job_id": "android-test",
                                "state_dir": "/remote/state",
                                "lines": 25,
                            },
                        },
                    }
                )

        self.assertTrue(response["result"].get("isError", False))
        self.assertEqual(response["result"]["structuredContent"]["returncode"], 7)
        self.assertEqual(response["result"]["structuredContent"]["log_kind"], "tail")
        argv = list(mocked_run.call_args.args[0])
        self.assertEqual(argv[:3], ["ssh", "-F", str(root / "ssh_config")])
        self.assertIn(DEFAULT_ANDROID_BUILD_SSH_TARGET, argv)
        remote = argv[-1]
        self.assertIn("tail -n \"$lines\" \"$log_path\"", remote)
        self.assertIn("lines=25", remote)

    def test_android_build_status_waits_without_running_log_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            server = self.make_server(root)
            with (
                patch("sailfish_devel_mcp.tools.run") as mocked_run,
                patch("sailfish_devel_mcp.tools.time.sleep"),
            ):
                mocked_run.side_effect = [
                    CommandResult(
                        ("ssh",),
                        0,
                        "job_id: android-test\nstate: running\nreturncode: \n",
                        "",
                    ),
                    CommandResult(
                        ("ssh",),
                        0,
                        "job_id: android-test\nstate: finished\nreturncode: 0\n",
                        "",
                    ),
                ]
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 53,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_android_build_status",
                            "arguments": {
                                "job_id": "android-test",
                                "wait_seconds": 10,
                                "poll_interval": 1,
                            },
                        },
                    }
                )

        structured = response["result"]["structuredContent"]
        self.assertEqual(mocked_run.call_count, 2)
        self.assertEqual(structured["polls"], 2)
        self.assertEqual(structured["state"], "finished")
        self.assertEqual(structured["log_kind"], "none")
        self.assertNotIn("command", structured)
        self.assertNotIn("stdout", structured["transport"])

    def test_android_build_failure_includes_bounded_excerpt_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            server = self.make_server(Path(tmp))
            initial = CommandResult(
                ("ssh",),
                0,
                "job_id: android-test\nstate: finished\nreturncode: 9\n",
                "",
            )
            diagnostic = CommandResult(
                ("ssh",),
                0,
                (
                    "job_id: android-test\nstate: finished\nreturncode: 9\n\n"
                    + "noise\n" * 200
                    + "error: useful failure\n"
                ),
                "",
            )
            with patch(
                "sailfish_devel_mcp.tools.run",
                side_effect=[initial, diagnostic],
            ) as mocked_run:
                response = server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 54,
                        "method": "tools/call",
                        "params": {
                            "name": "sailfish_android_build_status",
                            "arguments": {"job_id": "android-test"},
                        },
                    }
                )

        result = response["result"]
        structured = result["structuredContent"]
        self.assertEqual(mocked_run.call_count, 2)
        self.assertTrue(result.get("isError", False))
        self.assertEqual(structured["log_kind"], "failure_excerpt")
        self.assertNotIn("log_tail", structured)
        self.assertIn("error: useful failure", result["content"][0]["text"])
        self.assertLessEqual(structured["log_chars"], 6000)

    def write_fake_target(
        self,
        root: Path,
        name: str,
        *,
        ssu_release: str,
        version_id: str,
        flavour: str = "devel",
    ) -> None:
        target = root / "targets" / name
        (target / "etc" / "ssu").mkdir(parents=True)
        (target / "etc").mkdir(exist_ok=True)
        (target / "etc" / "ssu" / "ssu.ini").write_text(
            f"[General]\nregistered=true\nrelease={ssu_release}\nflavour={flavour}\n",
            encoding="utf-8",
        )
        (target / "etc" / "sailfish-release").write_text(
            f'VERSION_ID={version_id}\nSAILFISH_FLAVOUR="{flavour}"\n',
            encoding="utf-8",
        )

    def test_build_helper_selects_matching_local_sdk_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_sdk = root / "sdks" / "sfossdk" / "sdk-chroot"
            local_sdk.parent.mkdir(parents=True)
            local_sdk.touch()
            sdk_root = local_sdk.parent
            self.write_fake_target(sdk_root, "aarch64", ssu_release="live", version_id="5.2.0.4")
            self.write_fake_target(
                sdk_root,
                "aarch64-5.0.0",
                ssu_release="5.0.0",
                version_id="5.0.0.191",
            )

            self.assertEqual(build_sailfishos.normalize_release_tag("live"), "live")
            self.assertEqual(build_sailfishos.normalize_release_tag("devel"), "devel")
            self.assertEqual(build_sailfishos.normalize_local_release("devel"), "devel")
            live = build_sailfishos.select_local_sdk_builds(
                local_sdk,
                "live",
                ["aarch64"],
                False,
                root,
            )
            versioned = build_sailfishos.select_local_sdk_builds(
                local_sdk,
                "5.0.0",
                ["aarch64"],
                False,
                root,
            )
            missing = build_sailfishos.select_local_sdk_builds(
                local_sdk,
                "4.5.0",
                ["aarch64"],
                False,
                root,
            )
            exact_mismatch = build_sailfishos.select_local_sdk_builds(
                local_sdk,
                "5.0.0.55",
                ["aarch64"],
                False,
                root,
            )

        self.assertEqual(live, [build_sailfishos.LocalSdkBuild("aarch64", "aarch64")])
        self.assertEqual(
            versioned,
            [build_sailfishos.LocalSdkBuild("aarch64", "aarch64-5.0.0")],
        )
        self.assertIsNone(missing)
        self.assertIsNone(exact_mismatch)

    def test_build_helper_local_sdk_default_ignores_workflow_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "rpm").mkdir()
            (root / "rpm" / "sample.spec").write_text("Name: sample\n", encoding="utf-8")
            workflows = root / ".github" / "workflows"
            workflows.mkdir(parents=True)
            (workflows / "build.yml").write_text("env:\n  RELEASE: 5.0.0\n", encoding="utf-8")

            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(
                    build_sailfishos.requested_release((root,), None),
                    "5.0.0",
                )
                self.assertIsNone(build_sailfishos.explicit_requested_release(None))
                self.assertEqual(build_sailfishos.local_sdk_requested_release(None), "live")


if __name__ == "__main__":
    unittest.main()
