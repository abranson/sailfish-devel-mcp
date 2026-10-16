from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sailfish_devel_mcp import tools
from sailfish_devel_mcp.config import Config, PathConfig


class RuntimeIdentityTests(unittest.TestCase):
    def test_changes_additions_and_deletions_require_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'module.py'
            source.write_text('value = 1\n')
            startup = tools._source_identity(root)
            with patch.object(tools, '_SOURCE_ROOT', root), patch.object(tools, '_STARTUP_SOURCE', startup):
                self.assertFalse(tools._host_runtime_identity()['restart_needed'])
                (root / 'ignored.log').write_text('runtime output')
                self.assertFalse(tools._host_runtime_identity()['restart_needed'])
                source.write_text('value = 2\n')
                self.assertTrue(tools._host_runtime_identity()['restart_needed'])
                source.write_text('value = 1\n')
                added = root / 'new.py'
                added.write_text('')
                self.assertTrue(tools._host_runtime_identity()['restart_needed'])
                added.unlink()
                source.unlink()
                self.assertTrue(tools._host_runtime_identity()['restart_needed'])

    def test_unreadable_source_does_not_claim_current(self):
        with patch.object(tools, '_source_identity', return_value={'sha256': None, 'error': 'unreadable'}):
            self.assertIsNone(tools._host_runtime_identity()['restart_needed'])

    def test_build_status_preserves_provenance(self):
        metadata = {'provenance': {'commit': 'abc'}, 'artifact_checksums': {'test.rpm': 'digest'}}
        result = tools._compact_build_status({'build_metadata': metadata})
        self.assertEqual(result['provenance'], metadata['provenance'])
        self.assertEqual(result['artifact_checksums'], metadata['artifact_checksums'])

    def test_build_and_preflight_forward_spec_and_snapshot_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / 'helper.py'
            helper.write_text('')
            (root / 'rpm').mkdir()
            (root / 'rpm/sensorfw-qt5.spec').write_text('Name: sensorfw\n')
            config = Config(path=None, default_device=None, devices={},
                            paths=PathConfig(git_root=root, obs_root=root, build_sailfishos=helper))
            args = {'project_path': str(root), 'backend': 'local',
                    'spec_path': 'rpm/sensorfw-qt5.spec', 'snapshot_key': 'sensorfw',
                    'reset_snapshot': True}
            for dry_run in (False, True):
                command, _ = tools._sailfish_build_command(config, args, dry_run=dry_run)
                self.assertEqual(command[command.index('--spec') + 1], args['spec_path'])
                self.assertIn('--reset-snapshot', command)
            with self.assertRaisesRegex(ValueError, 'snapshot options'):
                tools._sailfish_build_command(config, dict(args, backend='docker'))
            for schema in (tools._spec_build_rpm(), tools._spec_build_preflight()):
                self.assertIn('spec_path', schema['inputSchema']['properties'])
                self.assertIn('reset_snapshot', schema['inputSchema']['properties'])
