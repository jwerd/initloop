import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from initloop.core import Inventory, Run, PolicyError, redact, snapshot, secret_like
from initloop.backend import DockerBackend


class CoreTests(unittest.TestCase):
    def test_computed_application_token_is_not_a_literal_credential(self):
        self.assertFalse(secret_like("$token=hash('sha256','local-demo-token');"))
        self.assertTrue(secret_like('SERVICE_TOKEN=actual-private-value'))
        self.assertTrue(secret_like('password = "actual-private-value"'))
    def test_unquoted_config_credentials_are_screened(self):
        for value in ('password: actual-private-value', 'token = actual-private-value',
                      'API_TOKEN: actual-private-value', '  password: actual-private-value', '  - API_TOKEN=actual-private-value',
                      'environment: {API_TOKEN: actual-private-value}', 'ENV SERVICE_TOKEN=actual-private-value'):
            with self.subTest(value=value):
                self.assertTrue(secret_like(value))

    def test_json_record_does_not_follow_predictable_temp_symlink(self):
        from initloop.core import write_json
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);valuable=root/'valuable';valuable.write_text('keep')
            path=root/'state.json';(root/'state.json.tmp').symlink_to(valuable)
            write_json(path,{'state':'safe'})
            self.assertEqual(valuable.read_text(),'keep')
            self.assertEqual(json.loads(path.read_text()),{'state':'safe'})
            self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'project'
        self.root.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)

    def track(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        subprocess.run(['git', '-C', str(self.root), 'add', name], check=True)

    def test_snapshot_preserves_source_excludes_secrets_and_untracked(self):
        self.track('main.py', 'print(1)')
        self.track('.env', 'API_KEY=never-send-this')
        (self.root / 'untracked.txt').write_text('private')
        dest = Path(self.tmp.name) / 'snapshot'
        result = snapshot(self.root, dest)
        self.assertEqual((dest / 'main.py').read_text(), 'print(1)')
        self.assertFalse((dest / '.env').exists())
        self.assertFalse((dest / 'untracked.txt').exists())
        self.assertIn('.env', result['excluded'])
        self.assertEqual((self.root / '.env').read_text(), 'API_KEY=never-send-this')
        self.assertEqual(dest.stat().st_mode & 0o777,0o755)

    def test_snapshot_binds_all_git_queries_to_selected_project(self):
        self.track('real.py', 'selected project')
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'initial'], check=True)
        head = subprocess.check_output(['git', '-C', str(self.root), 'rev-parse', 'HEAD']).decode().strip()
        other = Path(self.tmp.name) / 'other'
        subprocess.run(['git', 'init', '-q', str(other)], check=True)
        (other / 'scratch.txt').write_text('other project')
        subprocess.run(['git', '-C', str(other), 'add', '.'], check=True)
        (self.root / 'scratch.txt').write_text('untracked selected content')
        overrides = {'GIT_DIR': str(other / '.git'), 'GIT_WORK_TREE': str(other),
                     'GIT_COMMON_DIR': str(other / '.git'), 'GIT_INDEX_FILE': str(other / '.git/index'),
                     'GIT_OBJECT_DIRECTORY': str(other / '.git/objects'),
                     'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(other / '.git/objects')}
        for index, env in enumerate([overrides] + [{k: v} for k, v in overrides.items()]):
            with self.subTest(env=env), patch.dict(os.environ, env):
                dest = Path(self.tmp.name) / ('bound-' + str(index))
                result = snapshot(self.root, dest)
                self.assertEqual(result['files'], ['real.py'])
                self.assertEqual(result['revision'], head)
                self.assertFalse(result['dirty'])
                self.assertEqual((dest / 'real.py').read_text(), 'selected project')
                self.assertFalse((dest / 'scratch.txt').exists())
        (self.root / 'real.py').write_text('dirty selected project')
        for staged in (False, True):
            if staged:
                subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
            with patch.dict(os.environ, overrides):
                with self.assertRaisesRegex(PolicyError, 'include-dirty'):
                    snapshot(self.root, Path(self.tmp.name) / 'refused')
                result = snapshot(self.root, Path(self.tmp.name) / ('dirty-' + str(staged)), True)
                self.assertTrue(result['dirty'])
                self.assertEqual(result['revision'], head)
                self.assertEqual((Path(self.tmp.name) / ('dirty-' + str(staged)) / 'real.py').read_text(),
                                 'dirty selected project')

    def test_snapshot_supports_actual_worktree_and_initial_index_with_overrides(self):
        self.track('real.py', 'selected project')
        overrides = {'GIT_INDEX_FILE': str(Path(self.tmp.name) / 'absent-index')}
        with patch.dict(os.environ, overrides):
            initial = snapshot(self.root, Path(self.tmp.name) / 'initial')
        self.assertIsNone(initial['revision'])
        self.assertFalse(initial['dirty'])
        self.assertEqual(initial['files'], ['real.py'])
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Test',
                        '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'initial'], check=True)
        worktree = Path(self.tmp.name) / 'worktree'
        subprocess.run(['git', '-C', str(self.root), 'worktree', 'add', '--detach', str(worktree)],
                       check=True, capture_output=True)
        with patch.dict(os.environ, {'GIT_DIR': str(self.root / '.git'), 'GIT_WORK_TREE': str(self.root), **overrides}):
            result = snapshot(worktree, Path(self.tmp.name) / 'worktree-snapshot')
        self.assertEqual(result['files'], ['real.py'])
        self.assertIsNotNone(result['revision'])

    def test_reject_symlinks_and_nested_destination(self):
        (self.root / 'escape').symlink_to('/etc/passwd')
        subprocess.run(['git', '-C', str(self.root), 'add', 'escape'], check=True)
        with self.assertRaises(PolicyError):
            snapshot(self.root, Path(self.tmp.name) / 'out')
        with self.assertRaises(PolicyError):
            snapshot(self.root, self.root / 'out')

    def test_missing_git_and_dirty_default_fail_closed(self):
        self.track('main.py', 'a')
        (self.root / 'main.py').write_text('b')
        with self.assertRaises(PolicyError):
            snapshot(self.root, Path(self.tmp.name) / 'out')
        result = snapshot(self.root, Path(self.tmp.name) / 'explicit', include_dirty=True)
        self.assertTrue(result['dirty'])
        self.assertEqual((Path(self.tmp.name) / 'explicit/main.py').read_text(), 'b')

    def test_inventory_general_manifests_and_evidence(self):
        self.track('apps/api/pyproject.toml', '[project]\nname="api"')
        self.track('web/package.json', '{"scripts":{"test":"node test.js"}}')
        self.track('.env.example', 'DATABASE_URL=postgres://example\nQUEUE_HOST=queue')
        result = Inventory(self.root).scan()
        self.assertEqual(len(result['components']), 2)
        self.assertIn('DATABASE_URL', result['environment_names'])
        self.assertNotIn('postgres://example', json.dumps(result))
        self.assertTrue(all(f['state'] == 'observed' for f in result['findings']))

    def test_malformed_manifest_still_returns_useful_inventory(self):
        self.track('package.json','[]')
        self.track('other/composer.json','{"scripts":null}')
        result=Inventory(self.root).scan()
        self.assertEqual(len([f for f in result['findings'] if f['kind']=='invalid-manifest']),2)

    def test_secure_umask_keeps_runtime_inputs_readable(self):
        self.track('nested/main.py','print(1)')
        prior=os.umask(0o077)
        try:
            run=Run.create(self.root,Path(self.tmp.name)/'runs',{'objective':'setup','checks':[]})
            run.record_baseline([])
            repair=Path(run.patch({'new/README.md':'hello'})['workspace'])
        finally:
            os.umask(prior)
        self.assertEqual((run.root/'baseline/nested').stat().st_mode & 0o777,0o755)
        self.assertEqual((repair/'new').stat().st_mode & 0o777,0o755)
        self.assertEqual((repair/'new/README.md').stat().st_mode & 0o777,0o644)
        self.assertEqual(run.root.stat().st_mode & 0o777,0o700)

    def test_recognizable_credentials_in_source_are_not_snapshotted(self):
        self.track('config.py','OPENAI_API_KEY="sk-proj-abcdefghijklmnop"')
        with self.assertRaises(PolicyError): snapshot(self.root,Path(self.tmp.name)/'blocked-snapshot')
        self.assertFalse((Path(self.tmp.name)/'blocked-snapshot').exists())

    def test_run_acceptance_and_transitions_cannot_be_bypassed(self):
        self.track('main.py', 'pass')
        contract = {'objective':'read record', 'checks':[{'name':'record', 'argv':['python','check.py'], 'source':'user objective', 'exit_code':0}]}
        run = Run.create(self.root, Path(self.tmp.name) / 'runs', contract)
        with self.assertRaises(PolicyError):
            run.transition('verified')
        with self.assertRaises(PolicyError):
            run.patch({'../escape':'oops'})
        run.record_baseline([{'exit_code':1, 'stdout':'missing database'}])
        run.patch({'README.md':'Use python main.py'})
        self.assertEqual(run.state['phase'], 'repaired')
        run.contract_path.chmod(0o600)
        run.contract_path.write_text('{}')
        with self.assertRaises(PolicyError):
            run.verify(DockerBackend())

    def test_patch_cannot_change_frozen_input_or_allow_secrets(self):
        self.track('README.md', 'old')
        run = Run.create(self.root, Path(self.tmp.name)/'runs', {'objective':'setup','checks':[]})
        run.record_baseline([])
        for path in ['.env', '.git/config', '/etc/test', '../contract.json']:
            with self.assertRaises(PolicyError):
                run.patch({path:'x'})
        self.assertEqual((self.root/'README.md').read_text(), 'old')

    def test_docker_command_has_real_boundary(self):
        self.track('main.py', 'pass')
        backend = DockerBackend()
        argv = backend.command(self.root, 'sha256:'+'a'*64, ['python','main.py'], 'initloop-test')
        self.assertIn('--network=none', argv)
        self.assertIn('--read-only', argv)
        self.assertIn('--cap-drop=ALL', argv)
        self.assertIn('--user=65534:65534', argv)
        self.assertFalse(any('docker.sock' in a for a in argv))
        self.assertFalse(any('API_KEY' in a for a in argv))

    def test_redacts_tokens_urls_and_environment_assignments(self):
        value = redact('PASSWORD=hunter2 https://u:p@host/a?token=secret sk-proj-abcdefghijklmnop Bearer abcdefghijklmnop')
        for secret in ['hunter2','u:p','token=secret','abcdefghijklmnop']:
            self.assertNotIn(secret,value)

if __name__ == '__main__':
    unittest.main()
