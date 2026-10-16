import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import companion as c, companion_host as h, tools
from sailfish_devel_mcp.config import Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.runner import CommandResult


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.agent = self.root / 'agent.py'
        self.config = Config(path=None, default_device='test',
            devices={'test': DeviceConfig('test', 'root@test', username=pwd.getpwuid(os.getuid()).pw_name)},
            paths=PathConfig(git_root=self.root, obs_root=self.root))
        self.device = self.config.device()

    def shell_run(self, argv, timeout):
        p = subprocess.run(['sh', '-c', argv[-1]], capture_output=True, text=True, timeout=timeout)
        return CommandResult(tuple(argv), p.returncode, p.stdout, p.stderr)

    def route(self, source=None):
        if source:
            self.agent.write_text(source)
            (self.root / 'session.json').write_text('{}')
        with patch.object(h, 'AGENT_PATH', str(self.agent)), patch.object(tools, 'run', side_effect=self.shell_run):
            return h.routed(self.config, self.device, ['echo', 'companion-request'], timeout=2,
                            fallback='printf fallback >> ' + str(self.root/'effects') + '; echo legacy-result')

    def test_absent_and_incompatible_companion_use_retained_ssh_command(self):
        result = self.route()
        self.assertEqual(result.stdout.strip(), 'legacy-result')
        result = self.route('API_VERSION=1\n')
        self.assertEqual(result.stdout.strip(), 'legacy-result')
        self.assertEqual((self.root/'effects').read_text(), 'fallbackfallback')

    def test_companion_preferred_without_executing_fallback(self):
        result = self.route('''import json
API_VERSION=2
SESSION={}
def read_json(path): return {}
def session_config(value): return value
def dispatch(value):
 print(json.dumps(dict(companion_available=True,result=dict(returncode=0,stdout='device-result',stderr='',backend='companion'))))
''')
        self.assertEqual(result.stdout, 'device-result')
        self.assertEqual(result.metadata['backend'], 'companion')
        self.assertFalse((self.root/'effects').exists())

    def test_failed_companion_execution_never_replays_fallback(self):
        source = '''API_VERSION=2
SESSION={}
def read_json(path): return {}
def session_config(value): return value
def dispatch(value):
 raise RuntimeError('operation failed after mutation')
'''
        result = self.route(source)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('operation failed', result.stderr)
        self.assertFalse((self.root/'effects').exists())

    def test_stopped_companion_uses_fallback_before_execution(self):
        result = self.route('import json\nAPI_VERSION=2\nSESSION={}\ndef read_json(path): return {}\ndef session_config(value): return value\ndef dispatch(value): print(json.dumps(dict(companion_available=False)))\n')
        self.assertEqual(result.stdout.strip(), 'legacy-result')
        self.assertEqual((self.root/'effects').read_text(), 'fallback')

    def test_topmost_pid_uses_lipstick_method_on_both_paths(self):
        with patch.object(tools, '_run_device', return_value=CommandResult((), 0, '   int32 42', '')) as run:
            result = tools.handle_device_topmost_pid(self.config, {})
        self.assertEqual(result['structuredContent']['pid'], 42)
        self.assertEqual(run.call_args.args[2][-1], 'org.nemomobile.compositor.privateTopmostWindowProcessId')
        with patch.object(c, 'execute', return_value=dict(stdout='   int32 42')) as execute:
            result = c.foreground(str(self.root/'missing.desktop'), 0)
        self.assertEqual(result['foreground_pid'], 42)
        self.assertEqual(execute.call_args.args[0]['argv'][-1], 'org.nemomobile.compositor.privateTopmostWindowProcessId')

    def test_foreign_job_never_falls_back_when_companion_is_missing(self):
        job_id = 'device-test'
        directory = self.root/'device-commands'/job_id; directory.mkdir(parents=True)
        (directory/'companion.json').write_text(json.dumps({'device': dict(name='test', ssh_target='root@test')}))
        with patch.object(tools, '_device_command_jobs_dir', return_value=directory.parent), \
                patch.object(h, 'optional_call', return_value=None):
            result = h.job_operation(self.config, {'job_id': job_id})
        self.assertTrue(result['isError'])
        self.assertIn('No SSH fallback', result['content'][0]['text'])

    def test_failed_workflow_stops_before_next_mutation(self):
        marker = self.root/'marker'
        result = c.workflow({'steps': [dict(name='failure',argv=[sys.executable,'-c','raise SystemExit(7)'],timeout=2),
                           dict(name='must-not-run',argv=[sys.executable,'-c',"open(%r,'w').write('bad')" % str(marker)],timeout=2)]})
        self.assertEqual(len(result['steps']), 1)
        self.assertEqual(result['steps'][0]['returncode'], 7)
        self.assertFalse(marker.exists())

    def test_timeout_kills_descendants_even_after_leader_exit(self):
        pidfile=self.root/'pid'
        script="import subprocess,time; p=subprocess.Popen(['sleep','30']); open(%r,'w').write(str(p.pid)); time.sleep(30)" % str(pidfile)
        result=c.execute(dict(argv=[sys.executable,'-c',script],timeout=1))
        self.assertEqual(result['returncode'],124)
        pid=int(pidfile.read_text())
        self.assertIsNone(c.process_identity(pid))

    def test_session_operations_drop_root_and_set_correct_environment(self):
        user = pwd.getpwuid(os.getuid())
        session = dict(username=user.pw_name, runtime='/run/user/'+str(user.pw_uid), bus='unix:path=/run/user/'+str(user.pw_uid)+'/bus')
        with patch.object(c, 'SESSION', session), patch.object(c.os, 'getuid', return_value=0):
            argv=c.session_argv(['dbus-send','--session'])
        self.assertEqual(argv[:4], ['runuser','-u',user.pw_name,'--'])
        self.assertIn('HOME='+user.pw_dir,argv)
        self.assertIn('DBUS_SESSION_BUS_ADDRESS='+session['bus'],argv)


class DeviceJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.jobs=self.root/'jobs'
        self.install=self.root/'install';self.install.mkdir()
        launcher=self.install/'agent.py'
        launcher.write_text('import sys\nfrom sailfish_devel_mcp import companion as c\nc.job_worker(sys.argv[2])\n')
        for name,value in [('jobs_root',str(self.jobs)),('paths',(str(self.install),str(self.root/'unit'),str(self.root/'run')))]:
            p=patch.object(c,name,return_value=value);p.start();self.addCleanup(p.stop)

    def wait(self,job_id):
        result=c.job_status(dict(job_id=job_id,wait_seconds=5,lines=10))
        self.assertIn(result['state'],c.TERMINAL)
        return result

    def test_job_survives_client_and_records_failure_and_pages(self):
        receipt=c.job_start(dict(job_id='device-success',argv=[sys.executable,'-c',"import time;time.sleep(.1);print('device-job');raise SystemExit(7)"],timeout=3))
        self.assertIn(receipt['state'],('starting','running'))
        result=self.wait('device-success')
        self.assertEqual(result['returncode'],7)
        self.assertIn('device-job',result['log_tail'])
        page=c.job_status(dict(job_id='device-success',log_offset=0,max_bytes=6))
        self.assertEqual(page['next_offset'],6)
        self.assertFalse(page['eof'])

    def test_cancel_kills_child_after_leader_exit_and_is_idempotent(self):
        marker=self.root/'child'
        code="import subprocess; p=subprocess.Popen(['sleep','30']);open(%r,'w').write(str(p.pid))" % str(marker)
        args=dict(job_id='device-cancel',argv=[sys.executable,'-c',code],timeout=10)
        first=c.job_start(args)
        second=c.job_start(args)
        self.assertEqual(first['supervisor_pid'],second['supervisor_pid'])
        deadline=time.monotonic()+3
        while not marker.exists() and time.monotonic()<deadline: time.sleep(.02)
        self.assertTrue(marker.exists())
        result=c.job_cancel({'job_id':'device-cancel'})
        self.assertTrue(result['cancel_requested'])
        self.assertEqual(self.wait('device-cancel')['state'],'cancelled')
        self.assertIsNone(c.process_identity(int(marker.read_text())))

    def test_job_timeout_and_restart_detection(self):
        c.job_start(dict(job_id='device-timeout',argv=['sleep','30'],timeout=1))
        self.assertEqual(self.wait('device-timeout')['state'],'timed_out')
        directory=self.jobs/'device-lost'; directory.mkdir()
        c.write_json(str(directory/'status.json'),dict(job_id='device-lost',state='running',supervisor_pid=99999999,supervisor_identity='old'))
        self.assertEqual(c.job_state('device-lost')['failure_class'],'supervisor-lost')


if __name__ == '__main__': unittest.main()
