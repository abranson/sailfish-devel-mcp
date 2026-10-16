import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import companion as c
from sailfish_devel_mcp.companion_host import invoke
import pwd
from sailfish_devel_mcp.config import Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.runner import CommandResult
from sailfish_devel_mcp.tools import build_registry, handle_device_setup


class CompanionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        user = pwd.getpwuid(os.getuid())
        self.session = dict(username=user.pw_name, runtime='/run/user/' + str(user.pw_uid),
                            bus='unix:path=/run/user/' + str(user.pw_uid) + '/bus')
        patcher = patch.object(c, 'SESSION', self.session)
        patcher.start(); self.addCleanup(patcher.stop)
        for name, value in [('require_root', None), ('legacy_installed', False), ('active_jobs', [])]:
            patcher = patch.object(c, name, return_value=value)
            patcher.start(); self.addCleanup(patcher.stop)
        self.paths = (str(self.root/'install'), str(self.root/'units'/c.UNIT), str(self.root/'runtime'))
        self.config = Config(path=None, default_device='test',
            devices={'test': DeviceConfig(name='test', ssh_target='root@test', username='nemo')},
            paths=PathConfig(git_root=self.root, obs_root=self.root, ssh_config=self.root/'ssh',
                             build_sailfishos=self.root/'build.py', osc_api_alias='primary'))

    def test_initial_install_approval_and_update(self):
        source = Path(c.__file__).read_text()
        with patch.object(c, 'paths', return_value=self.paths), patch.object(c, 'command') as command, \
                patch.object(c, 'request', return_value={'version': c.VERSION}):
            with self.assertRaisesRegex(ValueError, 'explicit user permission'):
                c.manage('deploy', source)
            command.assert_not_called()
            self.assertFalse(Path(self.paths[0]).exists())
            installed = c.manage('deploy', source, True)
            self.assertFalse(installed['updated'])
            updated = c.manage('deploy', source + '\n')
            self.assertTrue(updated['updated'])
            self.assertEqual(c.manage('status')['sha256'], hashlib.sha256((source+'\n').encode()).hexdigest())
            extra = Path(self.paths[0])/'keep.txt'; extra.write_text('user data')
            c.manage('remove')
            self.assertEqual(extra.read_text(), 'user data')
            self.assertFalse(Path(self.paths[1]).exists())

    def test_lifecycle_refuses_active_jobs_before_changing_files(self):
        source = Path(c.__file__).read_text()
        with patch.object(c, 'paths', return_value=self.paths), patch.object(c, 'command') as command, \
                patch.object(c, 'request', return_value={'version': c.VERSION}):
            c.manage('deploy', source, True)
            command.reset_mock()
            with patch.object(c, 'active_jobs', return_value=['device-running']):
                for action in ('deploy', 'stop', 'remove'):
                    with self.assertRaisesRegex(ValueError, 'active companion jobs'):
                        c.manage(action, source + '\n')
            command.assert_not_called()
            self.assertEqual((Path(self.paths[0])/'agent.py').read_text(), source)

    def test_unknown_install_and_symlink_are_never_overwritten(self):
        with patch.object(c, 'paths', return_value=self.paths), patch.object(c, 'command') as command:
            Path(self.paths[0]).mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, 'unrecognized'):
                c.manage('deploy', 'pass', True)
            command.assert_not_called()
            Path(self.paths[0]).rmdir()
            Path(self.paths[0]).symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(ValueError):
                c.manage('deploy', 'pass', True)

    def test_bounded_events_cursor_loss_and_instance_reset(self):
        capture = c.Capture()
        for i in range(600):
            capture.record('test', str(i) + 'x' * 5000)
        result = capture.call('events', {'limit': 3})
        self.assertTrue(result['dropped'])
        self.assertEqual(result['next_after'], 91)
        self.assertEqual(len(result['events'][0]['text']), 4096)
        self.assertEqual(len(capture.lines), 512)
        self.assertTrue(capture.call('events', {'instance': 'old', 'after': 900})['reset'])
        self.assertEqual(capture.call('events', {'after': 600})['events'], [])

    def test_event_wait_wakes_on_capture(self):
        capture = c.Capture()
        timer = threading.Timer(0.05, lambda: capture.record('test', 'arrived'))
        timer.start()
        try:
            result = capture.call('events', {'wait_seconds': 1})
            self.assertEqual(result['events'][0]['text'], 'arrived')
        finally:
            timer.join()

    def test_capture_requires_filters_and_no_argument_injection(self):
        capture = c.Capture()
        for name, args in [
            ('capture_start', {'source': 'journal'}),
            ('capture_start', {'source': 'dbus'}),
            ('capture_start', {'source': 'dbus', 'interface': "x',eavesdrop='true"}),
            ('capture_start', {'source': 'journal', 'unit': '--help.service'}),
            ('events', {'limit': True}), ('events', {'wait_seconds': 20}),
        ]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                capture.call(name, args)

    def test_root_journal_uses_system_storage_with_user_uid_filter(self):
        capture = c.Capture()
        class Started(Exception):
            pass
        with patch.object(c.subprocess, 'Popen', side_effect=Started) as spawn:
            with self.assertRaises(Started):
                capture.call('capture_start', {'source': 'journal', 'unit': 'demo.service'})
        argv = spawn.call_args.args[0]
        self.assertIn('_SYSTEMD_USER_UNIT=demo.service', argv)
        self.assertIn('_UID=' + str(os.getuid()), argv)
        self.assertNotIn('--user', argv)

    def test_service_wait_matched_timeout_and_missing_unit(self):
        capture = c.Capture()
        with patch.object(c, 'command', return_value='LoadState=loaded\nActiveState=active'):
            self.assertTrue(capture.call('wait_service', {'unit': 'demo.service', 'state': 'active'})['matched'])
            self.assertTrue(capture.call('wait_service', {'unit': 'demo.service', 'state': 'inactive', 'wait_seconds': 0})['timed_out'])
        with patch.object(c, 'command', return_value='LoadState=not-found\nActiveState=inactive'):
            with self.assertRaisesRegex(ValueError, 'not found'):
                capture.call('wait_service', {'unit': 'demo.service', 'state': 'inactive'})

    def test_host_setup_routes_deployment_and_approval(self):
        report = {'ready': True, 'tools': {}}
        with patch('sailfish_devel_mcp.tools._handle_device_prerequisites', return_value={
                'structuredContent': report, 'isError': False}), \
                patch('sailfish_devel_mcp.companion_host.invoke', return_value={'structuredContent': {'installed': True}}) as call:
            result = handle_device_setup(self.config, {'companion': 'deploy', 'confirm_companion_install': True})
            self.assertTrue(result['structuredContent']['companion']['installed'])
            self.assertTrue(call.call_args.args[2]['confirm_initial_install'])
        self.assertIn('sailfish_device_companion_events', build_registry(self.config))
        schema = build_registry(self.config)['sailfish_device_companion_manage'].spec['inputSchema']
        self.assertNotIn('deploy', schema['properties']['action']['enum'])

    def test_host_does_not_claim_deployment_after_failure(self):
        with patch('sailfish_devel_mcp.runner.run', return_value=CommandResult(('ssh',), 1, '', 'denied')):
            result = invoke(self.config, 'manage', {'action': 'status'})
        self.assertTrue(result['isError'])
        self.assertEqual(result['structuredContent']['stderr'], 'denied')

    def test_python36_syntax_and_stdio_protocol(self):
        ast.parse(Path(c.__file__).read_text(), feature_version=(3, 6))
        messages = [dict(jsonrpc='2.0', id=1, method='initialize', params={'protocolVersion': '2024-11-05'}),
                    dict(jsonrpc='2.0', method='notifications/initialized'),
                    dict(jsonrpc='2.0', id=2, method='tools/list')]
        result = subprocess.run([sys.executable, c.__file__, '--stdio'],
                                input=''.join(json.dumps(m)+'\n' for m in messages),
                                capture_output=True, text=True, timeout=3)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]['result']['protocolVersion'], '2024-11-05')
        self.assertEqual(len(replies[1]['result']['tools']), 5)

    def test_idle_deadline_tracks_requests_and_jobs(self):
        with patch.object(c.time, 'monotonic', return_value=0) as clock:
            lifetime = c.IdleLifetime(3600)
            clock.return_value = 3599
            self.assertFalse(lifetime.expired())
            lifetime.begin()
            clock.return_value = 7200
            self.assertFalse(lifetime.expired())
            lifetime.finish()
            clock.return_value = 10799
            self.assertFalse(lifetime.expired())
            self.assertFalse(lifetime.expired(jobs_running=True))
            clock.return_value = 14399
            self.assertTrue(lifetime.expired())

    def test_capture_has_absolute_expiry_even_with_new_events(self):
        capture = c.Capture()
        process = unittest.mock.Mock()
        process.poll.return_value = None
        capture.process = process
        capture.started_at = 0
        with patch.object(c.time, 'monotonic', return_value=3600), patch.object(capture, 'stop') as stop:
            capture.record('journal', 'continuous output')
            capture.expire()
        stop.assert_called_once()
        self.assertTrue(capture.expired)
        self.assertIn('capture expired', capture.lines[-1]['text'])

    def test_on_demand_start_respects_explicit_pause_and_unknown_install(self):
        with patch.object(c, 'paths', return_value=self.paths), patch.object(c, 'command') as command, \
                patch.object(c, 'request', return_value={}) as request:
            self.assertFalse(c.ensure_running())
            command.assert_not_called()
            c.manage('deploy', Path(c.__file__).read_text(), True)
            c.manage('stop')
            command.reset_mock()
            self.assertFalse(c.ensure_running())
            command.assert_not_called()
            c.manage('start')
            command.reset_mock()
            request.side_effect = [FileNotFoundError(), {}]
            self.assertTrue(c.ensure_running())
            command.assert_called_once_with(['systemctl', 'start', c.UNIT], timeout=4)

    def test_real_daemon_exits_cleanly_after_active_request_and_idle_period(self):
        script = ('from sailfish_devel_mcp import companion as c; '
                  'c.paths=lambda: '+repr(self.paths)+'; c.SESSION='+repr(self.session)+'; '
                  'c.jobs_root=lambda: '+repr(str(self.root/'jobs'))+'; c.serve(idle_timeout=0.2)')
        process = subprocess.Popen([sys.executable, '-c', script], stderr=subprocess.PIPE)
        try:
            deadline = time.monotonic()+3
            while not (Path(self.paths[2])/'socket').exists():
                if process.poll() is not None or time.monotonic()>deadline:
                    self.fail('daemon failed to start')
                time.sleep(0.01)
            with patch.object(c, 'paths', return_value=self.paths):
                result = c.request('execute', {'argv': [sys.executable, '-c', 'import time; time.sleep(0.6); print("done")'], 'timeout': 2}, internal=True)
            self.assertEqual(result['returncode'], 0)
            self.assertEqual(result['stdout'].strip(), 'done')
            _, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertFalse((Path(self.paths[2])/'socket').exists())
        finally:
            if process.poll() is None:
                process.terminate()
                process.communicate(timeout=3)

    def test_real_daemon_capture_survives_client_disconnect(self):
        bindir = self.root/'bin'; bindir.mkdir()
        journal = bindir/'journalctl'
        journal.write_text('#!/bin/sh\ncase "$*" in *--disk-usage*) echo "Active journals take up 4K."; exit 0;; esac\nprintf "first\\n"\nsleep 0.2\nprintf "second\\n"\nsleep 30\n')
        journal.chmod(0o755)
        script = ('from sailfish_devel_mcp import companion as c; '
                  'c.paths=lambda: '+repr(self.paths)+'; c.SESSION='+repr(self.session)+'; c.serve(capture_timeout=0.5)')
        process = subprocess.Popen([sys.executable, '-c', script], stderr=subprocess.PIPE,
            env=dict(os.environ, PATH=str(bindir)+':'+os.environ['PATH']))
        try:
            deadline = time.monotonic()+3
            while not (Path(self.paths[2])/'socket').exists():
                if process.poll() is not None or time.monotonic()>deadline:
                    self.fail('daemon failed to start')
                time.sleep(0.01)
            with patch.object(c, 'paths', return_value=self.paths):
                status = c.request('status', {})
                self.assertFalse(status['capturing'])
                c.request('capture_start', {'source': 'journal', 'unit': 'demo.service'})
                result = c.request('events', {'wait_seconds': 1})
                result = c.request('events', {'after': result['next_after'], 'wait_seconds': 1})
                self.assertIn('second', [event['text'] for event in result['events']])
                # Continued client polling keeps the daemon alive but must not
                # extend the capture's absolute deadline.
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    stopped = c.request('status', {})
                    if stopped['capture_expired']:
                        break
                    time.sleep(0.05)
                self.assertTrue(stopped['capture_expired'])
                self.assertFalse(stopped['capturing'])
                self.assertGreaterEqual(len(c.request('events', {})['events']), 2)
                mode = (Path(self.paths[2])/'socket').stat().st_mode & 0o777
                self.assertEqual(mode, 0o600)
        finally:
            process.terminate()
            _, stderr = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 0, stderr.decode())


if __name__ == '__main__':
    unittest.main()
