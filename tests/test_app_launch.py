from pathlib import Path
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from sailfish_devel_mcp.config import Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.runner import CommandResult
from sailfish_devel_mcp.tools import _app_launch_script, build_registry, handle_device_app_launch


class AppLaunchTests(unittest.TestCase):
    def config(self, root):
        return Config(path=None, default_device='test',
                      devices={'test': DeviceConfig(name='test', ssh_target='root@test', username='nemo')},
                      paths=PathConfig(git_root=root, obs_root=root, ssh_config=root/'ssh_config',
                                       build_sailfishos=root/'build.py', osc_api_alias='primary-api'))

    def test_registry_and_session_user_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.config(Path(tmp))
            tool = build_registry(config)['sailfish_device_app_launch']
            with patch('sailfish_devel_mcp.tools.run') as run:
                run.return_value = CommandResult(('ssh',), 0,
                    'launch_pid=42\nremote_log=/home/nemo/log\nremote_status=/home/nemo/status\n', '')
                result = tool.handler({'desktop_file': 'sailfish-browser.desktop'})
            self.assertFalse(result['isError'])
            self.assertTrue(result['structuredContent']['submitted'])
            self.assertEqual(result['structuredContent']['launch_pid'], 42)
            self.assertIsNone(result['structuredContent']['launch_exit_code'])
            remote = run.call_args.args[0][-1]
            self.assertIn('runuser -u nemo', remote)
            self.assertIn('/usr/share/applications/sailfish-browser.desktop', remote)

    def test_rejected_inputs_never_reach_ssh(self):
        with tempfile.TemporaryDirectory() as tmp, patch('sailfish_devel_mcp.tools.run') as run:
            config = self.config(Path(tmp))
            for name in ('../bad.desktop', 'dir/app.desktop', '/tmp/../bad.desktop',
                         '-bad.desktop', 'app.txt', 'bad\napp.desktop', 'bad\0app.desktop'):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    handle_device_app_launch(config, {'desktop_file': name})
            with self.assertRaises(ValueError):
                handle_device_app_launch(config, {'desktop_file': 'app.desktop', 'timeout': 1})
            run.assert_not_called()

    def test_launch_failure_is_not_submission(self):
        with tempfile.TemporaryDirectory() as tmp, patch('sailfish_devel_mcp.tools.run') as run:
            run.return_value = CommandResult(('ssh',), 7, 'launch_pid=42\nlaunch_exit_code=7\n', 'failed')
            result = handle_device_app_launch(self.config(Path(tmp)), {'desktop_file': 'app.desktop'})
            self.assertTrue(result['isError'])
            self.assertFalse(result['structuredContent']['submitted'])
            self.assertEqual(result['structuredContent']['launch_exit_code'], 7)

    def run_script(self, gio_body, wait='1'):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        home = root/'user home'; home.mkdir()
        bindir = root/'bin'; bindir.mkdir()
        desktop = home/'$(touch INJECTED); app.desktop'; desktop.touch()
        scripts = {
            'getent': '#!/bin/sh\nprintf "nemo:x:1000:1000::%s:/bin/sh\\n" "$TEST_HOME"\n',
            'gio': '#!/bin/sh\n' + gio_body,
        }
        for name, source in scripts.items():
            p = bindir/name; p.write_text(source); p.chmod(0o755)
        env = dict(os.environ, PATH=str(bindir)+':'+os.environ['PATH'], TEST_HOME=str(home))
        result = subprocess.run(['sh', '-c', _app_launch_script(), 'app-launch',
                                 'nemo', str(desktop), wait], env=env,
                                capture_output=True, text=True, timeout=3)
        receipt = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        return result, receipt, home, desktop

    def test_real_shell_quotes_paths_sets_home_and_reports_failure(self):
        result, receipt, home, desktop = self.run_script(
            'printf "%s\\n%s\\n%s\\n" "$PWD" "$HOME" "$2"\nexit 7\n')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(receipt['launch_exit_code'], '7')
        self.assertEqual(Path(receipt['remote_log']).read_text().splitlines(),
                         [str(home), str(home), str(desktop)])
        self.assertFalse((home/'INJECTED').exists())
        self.assertEqual(Path(receipt['remote_log']).stat().st_mode & 0o777, 0o600)

    def test_real_shell_releases_streams_while_descendant_lives(self):
        start = time.monotonic()
        result, receipt, home, desktop = self.run_script('sleep 4 &\nexit 0\n', wait='0')
        self.assertEqual(result.returncode, 0)
        self.assertLess(time.monotonic()-start, 3)
        status = Path(receipt['remote_status'])
        for _ in range(50):
            if status.exists():
                break
            time.sleep(0.01)
        self.assertEqual(status.read_text().strip(), '0')


if __name__ == '__main__':
    unittest.main()
