import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import tools
from sailfish_devel_mcp.config import Config, DeviceConfig, PathConfig
from sailfish_devel_mcp.runner import CommandResult
from sailfish_devel_mcp.server import McpServer, run_stdio
from sailfish_devel_mcp.qml import ternary_translation_findings
from sailfish_devel_mcp.vendor import build_sailfishos as helper


class ReviewFixTests(unittest.TestCase):
    def config(self, root):
        return Config(path=None, default_device='test', devices={'test': DeviceConfig('test', 'root@test')},
                      paths=PathConfig(git_root=root, obs_root=root/'OBS', ssh_config=root/'ssh_config',
                                       build_sailfishos=Path(helper.__file__),
                                       obs_servers={'primary': 'primary-api'}))

    def test_malformed_request_does_not_stop_transport(self):
        for malformed in (None, {}, {'jsonrpc': '1.0', 'id': 1, 'method': 'ping'},
                          {'jsonrpc': '2.0', 'id': 1, 'method': 7}):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as d:
                stream = io.StringIO(json.dumps(malformed)+'\n'+json.dumps({'jsonrpc':'2.0','id':2,'method':'ping'})+'\n')
                output = io.StringIO()
                with contextlib.redirect_stderr(io.StringIO()):
                    run_stdio(McpServer(self.config(Path(d))), stream, output)
                responses = [json.loads(line) for line in output.getvalue().splitlines()]
                self.assertEqual(responses[0]['error']['code'], -32600)
                self.assertEqual(responses[1]['result'], {})

    def test_nested_build_root_and_metadata_agree(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); child=root/'source'; (child/'rpm').mkdir(parents=True)
            (child/'rpm'/'sample.spec').write_text('Name: sample\n')
            with patch.object(tools, '_start_background_command', return_value={'job_id':'test'}) as start:
                # The receipt needs no job files to validate the launch plan.
                with patch.object(tools, '_job_receipt', return_value={}):
                    with patch.object(tools, 'ok_text', return_value={}):
                        start.return_value.update(status_path='status', log_path='log')
                        tools.handle_build_rpm(self.config(root), {'project_path':str(root)})
                self.assertEqual(start.call_args.kwargs['metadata_path'], child/'.mb2'/helper.BUILD_METADATA_NAME)
                command=start.call_args.args[1]
                self.assertEqual(command[command.index('--project-dir')+1], str(child))

    def test_vcs_option_preserves_omission_and_both_explicit_values(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'rpm').mkdir();(root/'rpm'/'sample.spec').touch()
            for value in (None, False, True):
                args={'project_path':str(root),'backend':'local'}
                if value is not None:args['no_vcs_apply']=value
                command,_=tools._sailfish_build_command(self.config(root), args)
                self.assertEqual('--vcs-apply' in command, value is False)
                self.assertEqual('--no-vcs-apply' in command, value is True)

    def test_qml_multiline_requires_comments_on_each_branch(self):
        source='''Item {
 property string text: ready
   ? qsTrId("yes")
   : qsTrId("no")
}'''
        self.assertEqual(len(ternary_translation_findings(source)),2)
        valid='''Item {
 property string text: ready ?
   //: affirmative answer
   //% "Yes"
   qsTrId("yes") :
   //: negative answer
   //% "No"
   qsTrId("no")
}'''
        self.assertEqual(ternary_translation_findings(valid),[])
        self.assertEqual(len(ternary_translation_findings(valid.replace('//: negative answer','// other comment'))),1)
        self.assertEqual(ternary_translation_findings('Item { text: "? qsTrId(foo) :"; // ? qsTrId(bar) :\n}'),[])

    def test_log_tail_and_pages_bound_long_lines(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'log';path.write_bytes(b'x'*200000+b'END')
            tail=tools._tail_file(path,1000)
            self.assertLessEqual(len(tail),12100);self.assertTrue(tail.endswith('END'))
            text,page=tools._log_page(path,199999,3)
            self.assertEqual(text,'xEN');self.assertEqual(page,{'next_offset':200002,'eof':False})
            text,page=tools._log_page(path,page['next_offset'],3)
            self.assertEqual(text,'D');self.assertTrue(page['eof'])
            with self.assertRaises(ValueError):tools._log_page(path,999999,3)

    def test_status_revision_suppresses_repeated_failure_but_not_requested_log(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);job=root/'builds'/'test';job.mkdir(parents=True)
            (job/'build.log').write_text('error: example\n')
            tools._write_json_atomic(job/'status.json',{'job_id':'test','state':'failed','returncode':1})
            with patch.dict(os.environ,{'SAILFISH_DEVEL_MCP_STATE_DIR':str(root)}):
                first=tools.handle_build_status(self.config(root),{'job_id':'test'})
                args={'job_id':'test','after_revision':first['structuredContent']['revision']}
                repeated=tools.handle_build_status(self.config(root),args)
                self.assertTrue(repeated['structuredContent']['unchanged']);self.assertTrue(repeated['isError'])
                self.assertNotIn('error: example',repeated['content'][0]['text'])
                page=tools.handle_build_status(self.config(root),{**args,'log_offset':0,'max_bytes':6})
                self.assertEqual(page['structuredContent']['next_offset'],6)
                self.assertFalse(page['structuredContent'].get('unchanged',False))
                tools._write_json_atomic(job/'status.json',{'job_id':'test','state':'finished','returncode':0})
                changed=tools.handle_build_status(self.config(root),args)
                self.assertNotEqual(changed['structuredContent']['revision'],args['after_revision'])

    def test_compact_status_exposes_build_outcome_metadata(self):
        result=tools._compact_build_status({'job_id':'test','argv':['secret'], 'pid':123,
            'build_metadata':{'helper_version':'2.4.0','backend':'local','rpmlint':{'warnings':2},
            'builds':[{'arch':'aarch64','target':'aarch64-project','dependency_diagnostics':[{'requirement':'example'}]}]}})
        self.assertEqual(result['rpmlint']['warnings'],2)
        self.assertEqual(result['builds'][0]['target'],'aarch64-project')
        self.assertNotIn('argv',result);self.assertNotIn('pid',result)

    def test_cli_wait_and_detached_install_transaction(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); fake=root/'bin';fake.mkdir()
            record=root/'commands'
            for name in ('ssh','scp'):
                path=fake/name
                path.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_COMMAND_RECORD"\n')
                path.chmod(0o755)
            rpms=[root/'one.rpm',root/'two.rpm']
            for rpm in rpms:rpm.touch()
            env={'SAILFISH_DEVEL_MCP_STATE_DIR':str(root/'state'),'PATH':str(fake)+os.pathsep+os.environ['PATH'],
                 'TEST_COMMAND_RECORD':str(record),'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')}
            with patch.dict(os.environ,env):
                receipt=tools.handle_device_install_rpm(self.config(root),{'rpm_paths':[str(p) for p in rpms]})
                self.assertFalse(receipt['isError'])
                job=receipt['structuredContent']['job_id']
                process=subprocess.run([sys.executable,'-m','sailfish_devel_mcp.jobs','wait','--job-id',job,
                                        '--timeout','10','--interval','0.05'],capture_output=True,text=True,timeout=12)
                self.assertEqual(process.returncode,0,process.stdout+process.stderr)
                result=json.loads(process.stdout)
                self.assertEqual(result['structuredContent']['state'],'finished')
            lines=record.read_text().splitlines()
            installs=[line for line in lines if 'pkcon install-local' in line]
            self.assertEqual(len(installs),1)
            self.assertIn('one.rpm',installs[0]);self.assertIn('two.rpm',installs[0])

    def test_sdk_refresh_is_detached_and_uses_shared_wrapper(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch.object(tools,'_local_sdk_path',return_value=Path('/srv/mer/sdks/sfossdk/sdk-chroot')):
                with patch.object(tools,'_start_background_command',return_value={'job_id':'test'}) as start:
                    result=tools.handle_sdk_refresh_metadata(self.config(root),{'target':'aarch64-project.default'})
            self.assertEqual(result['structuredContent']['job_id'],'test')
            self.assertIn('sb2 -t aarch64-project.default',start.call_args.args[1][-1])
            self.assertNotIn('.default.default',start.call_args.args[1][-1])

    def test_obs_watch_uses_provider_native_watcher(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(tools,'_start_background_command',return_value={'job_id':'test'}) as start:
                tools.handle_obs_watch(self.config(Path(d)),{'server':'primary','project':'home:test','package':'sample'})
            self.assertEqual(start.call_args.args[1],['osc','-A','primary-api','results','--watch','--fail-on-error','home:test','sample'])

    def test_obs_wait_honors_total_deadline(self):
        clock=[0.0];timeouts=[]
        def run(command,timeout):
            timeouts.append(timeout);clock[0]+=2
            return CommandResult(tuple(command),0,'building','')
        def sleep(seconds):clock[0]+=seconds
        with tempfile.TemporaryDirectory() as d, patch.object(tools,'run',side_effect=run), \
             patch.object(tools.time,'monotonic',side_effect=lambda:clock[0]),patch.object(tools.time,'sleep',side_effect=sleep):
            result=tools.handle_obs_results(self.config(Path(d)),{'project':'test','wait_seconds':3})
        self.assertEqual(timeouts,[3]);self.assertEqual(clock[0],3)
        self.assertTrue(result['structuredContent']['wait_expired'])

    def test_vendored_manifest_matches_contents(self):
        path=Path(helper.__file__);manifest=json.loads(path.with_name('build-helper.json').read_text())
        self.assertEqual(manifest['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(manifest['helper_version'],helper.HELPER_VERSION)

    def test_doctor_does_not_contact_devices(self):
        with tempfile.TemporaryDirectory() as d,patch.object(tools,'run',side_effect=AssertionError('unexpected subprocess')):
            report=tools.handle_doctor(self.config(Path(d)),{})['structuredContent']
        self.assertTrue(report['helper_matches_vendor'])
        self.assertIn('docker',report['tools'])


if __name__=='__main__':unittest.main()
