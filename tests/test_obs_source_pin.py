from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from sailfish_devel_mcp import tools
from sailfish_devel_mcp.config import Config, PathConfig
from sailfish_devel_mcp.obs import edit_source_pin, service_sha256, source_pins
from sailfish_devel_mcp.runner import CommandResult, run
from sailfish_devel_mcp.server import McpServer


SOURCE = '''<?xml version="1.0" encoding="UTF-8"?>
<services>
  <!-- Keep this: café -->
  <service name="tar_git">
    <param name="url">https://example.invalid/repo.git</param>
    <param name='branch'>feature</param>
    <param name="revision">old</param>
    <param name="token">private-test-value</param>
  </service>
  <service name="recompress" mode="disabled" />
</services>
'''


def listing(source=SOURCE, revision='41'):
    digest = hashlib.md5(source.encode('utf-8'), usedforsecurity=False).hexdigest()
    return f'<directory rev="{revision}"><entry name="_service" md5="{digest}"/></directory>'


class SourcePinXmlTests(unittest.TestCase):
    def test_preserves_everything_except_requested_values(self):
        source = SOURCE.replace('\n', '\r\n')
        updated, change = edit_source_pin(source, source_pins(source), None, 'new<&', 'next')
        self.assertEqual(updated, source.replace('>old<', '>new&lt;&amp;<').replace('>feature<', '>next<'))
        self.assertEqual(change['changes']['revision'], {'before': 'old', 'after': 'new<&'})
        self.assertEqual(source_pins(updated)[0]['params']['revision']['value'], 'new<&')

    def test_multiple_services_require_selection(self):
        source = SOURCE.replace('</services>', '<service name="obs_scm"><param name="revision">other</param></service></services>')
        pins = source_pins(source)
        self.assertEqual([pin['service_index'] for pin in pins], [0, 2])
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            edit_source_pin(source, pins, None, 'new', None)
        updated, _ = edit_source_pin(source, pins, 2, 'new', None)
        self.assertEqual(updated, source.replace('>other<', '>new<'))

    def test_rejects_invalid_ambiguous_or_entity_xml(self):
        sources = [
            '<broken', '<wrong/>',
            '<!DOCTYPE services [<!ENTITY pin "old">]><services/>',
            SOURCE.replace('>old<', '><nested/><'),
            SOURCE.replace('</service>', '<param name="revision">other</param></service>', 1),
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                source_pins(source)

    def test_refuses_missing_empty_or_complex_pin_parameters(self):
        sources = [
            SOURCE.replace('<param name="revision">old</param>', ''),
            SOURCE.replace('<param name="revision">old</param>', '<param name="revision"/>'),
            SOURCE.replace('>old<', '>old<!-- comment --><'),
            SOURCE.replace("<param name='branch'>feature</param>", ''),
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                edit_source_pin(source, source_pins(source), None, 'new', 'next')

    def test_rejects_empty_and_control_character_values(self):
        for value in ('', ' ', 'a\nb', 'a\x00b'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                edit_source_pin(SOURCE, source_pins(SOURCE), None, value, None)

    def test_quoted_angle_bracket_in_attributes_and_entities(self):
        source = SOURCE.replace('name="revision"', 'note="a > b" name="revision"').replace('>old<', '>old&amp;tag<')
        updated, _ = edit_source_pin(source, source_pins(source), None, 'new', None)
        self.assertEqual(updated, source.replace('>old&amp;tag<', '>new<'))


class ObsSourcePinTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.config = Config(path=None, default_device=None, devices={},
                             paths=PathConfig(git_root=root, obs_root=root,
                                              osc_api_alias='primary-api',
                                              obs_servers={'secondary': 'secondary-api'}))
        self.args = {'project': 'home:example:feature', 'package': 'sample'}
        self.which = patch.object(tools.shutil, 'which', return_value='/usr/bin/osc').start()
        self.addCleanup(patch.stopall)

    def result(self, output=SOURCE, code=0):
        return CommandResult(('osc',), code, output, 'failure' if code else '')

    def apply_args(self, **extra):
        return {**self.args, 'action': 'apply', 'revision': 'new',
                'expected_sha256': service_sha256(SOURCE), 'comment': 'Pin sample source', **extra}

    def test_default_read_and_preview_never_write_or_expose_private_parameters(self):
        for extra in ({}, {'action': 'preview', 'revision': 'new'}):
            with self.subTest(extra=extra), patch.object(tools, 'run', return_value=self.result()) as runner:
                response = tools.handle_obs_source_pin(self.config, {**self.args, **extra})
            self.assertFalse(response.get('isError', False))
            self.assertEqual(runner.call_count, 1)
            self.assertNotIn('-X', runner.call_args.args[0])
            self.assertNotIn('private-test-value', json.dumps(response))
            self.assertEqual(response['structuredContent']['sha256'], service_sha256(SOURCE))

    def test_apply_uploads_only_service_with_comment_then_verifies_committed_revision(self):
        uploaded = []
        commands = []
        updated = SOURCE.replace('>old<', '>new<')

        def execute(argv, **kwargs):
            commands.append(argv)
            self.assertFalse(kwargs['text'])
            self.assertLessEqual(kwargs['timeout'], 15)
            if '-T' in argv:
                path = Path(argv[argv.index('-T') + 1])
                uploaded.append(path)
                self.assertEqual(path.read_text(), updated)
                query = parse_qs(urlsplit(argv[-1]).query)
                # A rev parameter would create an internal revision instead of a commit.
                self.assertEqual(query, {'comment': ['Pin sample source']})
                return self.result('<revision rev="42"><srcmd5>abc</srcmd5></revision>')
            if 'rev=upload' in argv[-1]:
                self.assertTrue(urlsplit(argv[-1]).path.endswith('/sample'))
                return self.result(listing())
            return self.result(updated if 'rev=42' in argv[-1] else SOURCE)

        with patch.object(tools, 'run', side_effect=execute):
            response = tools.handle_obs_source_pin(self.config, self.apply_args(server='secondary'))
        self.assertEqual(response['structuredContent']['status'], 'applied')
        self.assertEqual(response['structuredContent']['obs_revision'], '42')
        self.assertEqual(len(commands), 4)
        self.assertEqual(commands[0][:3], ['osc', '-A', 'secondary-api'])
        self.assertIn('/home%3Aexample%3Afeature/sample/_service?', commands[0][-1])
        self.assertTrue(all(not path.exists() for path in uploaded))

    def test_stale_preview_or_concurrent_edit_never_uploads(self):
        changed = SOURCE.replace('feature', 'another-branch')
        for responses in ([self.result(changed)], [self.result(), self.result(listing(changed))]):
            with self.subTest(count=len(responses)), patch.object(tools, 'run', side_effect=responses) as runner:
                response = tools.handle_obs_source_pin(self.config, self.apply_args())
            self.assertTrue(response['isError'])
            self.assertEqual(response['structuredContent']['status'], 'conflict')
            self.assertTrue(all('-X' not in call.args[0] for call in runner.call_args_list))

    def test_no_op_does_not_commit(self):
        with patch.object(tools, 'run', return_value=self.result()) as runner:
            response = tools.handle_obs_source_pin(self.config, self.apply_args(revision='old'))
        self.assertEqual(response['structuredContent']['status'], 'unchanged')
        self.assertEqual(runner.call_count, 1)

    def test_failed_or_unparseable_write_is_unknown_and_never_retried(self):
        for receipt in (self.result('partial', 124), self.result('not XML'), self.result('<status code="ok"/>')):
            with self.subTest(receipt=receipt), patch.object(tools, 'run', side_effect=[self.result(), self.result(listing()), receipt]) as runner:
                response = tools.handle_obs_source_pin(self.config, self.apply_args())
            self.assertEqual(response['structuredContent']['status'], 'unknown')
            self.assertFalse(response['structuredContent']['retry_safe'])
            self.assertEqual(runner.call_count, 3)

    def test_failed_or_mismatched_readback_keeps_commit_receipt(self):
        for readback in (self.result('', 124), self.result()):
            with self.subTest(readback=readback), patch.object(tools, 'run', side_effect=[
                    self.result(), self.result(listing()), self.result('<revision rev="42"/>'), readback]) as runner:
                response = tools.handle_obs_source_pin(self.config, self.apply_args())
            self.assertTrue(response['isError'])
            self.assertEqual(response['structuredContent']['status'], 'committed_unverified')
            self.assertEqual(response['structuredContent']['obs_revision'], '42')
            self.assertEqual(runner.call_count, 4)

    def test_read_and_recheck_failures_do_not_write_or_expose_partial_xml(self):
        for responses in ([self.result(SOURCE, 124)], [self.result(), self.result(SOURCE, 124)]):
            with self.subTest(count=len(responses)), patch.object(tools, 'run', side_effect=responses) as runner:
                response = tools.handle_obs_source_pin(self.config, self.apply_args())
            self.assertTrue(response['isError'])
            self.assertNotIn('private-test-value', json.dumps(response))
            self.assertTrue(all('-X' not in call.args[0] for call in runner.call_args_list))

    def test_invalid_arguments_fail_before_commands(self):
        cases = [dict(self.args, action='apply', revision='new'),
                 self.apply_args(expected_sha256='invalid'), self.apply_args(comment=' '),
                 dict(self.args, action='preview'), dict(self.args, revision='new'),
                 dict(self.args, project='../other'), dict(self.args, package='..'),
                 dict(self.args, server='secondary', api_alias='primary'),
                 dict(self.args, server='missing'), dict(self.args, timeout=16)]
        for args in cases:
            with self.subTest(args=args), patch.object(tools, 'run') as runner, self.assertRaises(ValueError):
                tools.handle_obs_source_pin(self.config, args)
            runner.assert_not_called()

    def test_missing_osc_reports_dependency(self):
        self.which.return_value = None
        with patch.object(tools, 'run') as runner:
            response = tools.handle_obs_source_pin(self.config, self.args)
        self.assertTrue(response['isError'])
        self.assertIn('osc is required', response['content'][0]['text'])
        runner.assert_not_called()

    def test_deadline_expires_before_upload(self):
        with patch.object(tools, 'run', side_effect=[self.result(), self.result(listing())]) as runner, \
                patch.object(tools.time, 'monotonic', side_effect=[0, 0, 1, 16]):
            response = tools.handle_obs_source_pin(self.config, self.apply_args())
        self.assertEqual(response['structuredContent']['status'], 'not_applied')
        self.assertEqual(runner.call_count, 2)

    def test_staged_uploads_and_invalid_file_lists_are_not_committed(self):
        for xml in (listing(revision='upload'), '<directory rev="41"/>', 'broken', '<status code="ok"/>'):
            with self.subTest(xml=xml), patch.object(tools, 'run', side_effect=[self.result(), self.result(xml)]) as runner:
                response = tools.handle_obs_source_pin(self.config, self.apply_args())
            self.assertEqual(response['structuredContent']['status'], 'conflict')
            self.assertEqual(runner.call_count, 2)

    def test_registry_and_protocol_expose_mutating_tool_with_read_default(self):
        server = McpServer(self.config)
        spec = server.registry['sailfish_obs_source_pin'].spec
        self.assertFalse(spec['annotations']['readOnlyHint'])
        self.assertEqual(spec['inputSchema']['properties']['action']['default'], 'read')
        with patch.object(tools, 'run', return_value=self.result()):
            response = server.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                      'params': {'name': spec['name'], 'arguments': self.args}})
        self.assertEqual(response['result']['structuredContent']['status'], 'read')

    def test_runner_can_preserve_service_line_endings(self):
        response = run(['python3', '-c', 'import sys; sys.stdout.buffer.write(b"a\\r\\nb\\r\\n")'], text=False)
        self.assertEqual(response.stdout, 'a\r\nb\r\n')


if __name__ == '__main__':
    unittest.main()
