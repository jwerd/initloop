"""Controller regressions: frozen inputs, literal credentials and reviewable repairs."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from initloop.core import PolicyError, Run, redact, secret_like, snapshot
from initloop.native import NativeBackend


class CoreHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)
        self.source = self.parent / 'source'
        self.source.mkdir()
        subprocess.run(['git', 'init', '-q', str(self.source)], check=True)
        self.put('check.py', 'print("expected")\n')

    def put(self, name, text):
        target = self.source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        subprocess.run(['git', '-C', str(self.source), 'add', '--', name], check=True)
        return target

    def freeze(self, checks=None):
        run = Run.create(self.source, self.parent / 'runs', {
            'objective': 'exercise useful behavior', 'protected_paths': ['check.py'],
            'checks': checks or []})
        run.record_baseline([{'exit_code': 1}])
        return run

    def test_mutated_frozen_baseline_content_and_modes_are_refused(self):
        for mutation in ('content', 'mode'):
            with self.subTest(mutation=mutation):
                run = self.freeze()
                target = run.root / 'baseline/check.py'
                if mutation == 'content':
                    target.write_text('print("tampered")\n')
                else:
                    target.chmod(0o755)
                with self.assertRaisesRegex(PolicyError, 'baseline'):
                    run.patch({'README.md': 'unrelated documentation\n'})
                self.assertEqual(run.state['attempts'], 0)
                self.assertFalse((run.root / 'repair-1').exists())

    def test_baseline_mutation_during_copy_is_refused(self):
        run = self.freeze()
        original = shutil.copytree
        def mutate_after_copy(*args, **kwargs):
            result = original(*args, **kwargs)
            (run.root / 'baseline/check.py').write_text('print("changed")\n')
            return result
        with patch('initloop.core.shutil.copytree', side_effect=mutate_after_copy):
            with self.assertRaisesRegex(PolicyError, 'baseline'):
                run.patch({'README.md': 'docs\n'})
        self.assertEqual(run.state['attempts'], 0)
        self.assertFalse((run.root / 'repair-1').exists())

    def test_benign_computed_and_default_credentials_snapshot_and_repair(self):
        examples = [
            'token = os.getenv("TOKEN")', 'token = secrets.token_hex(32)',
            'def authenticate(token=None):\n    pass',
            'const token = request.headers.authorization;',
            'token = os.environ["TOKEN"]', 'token = null;', 'token = undefined;',
            'password = ""', 'token = false', '$token=hash("sha256", "local-demo");',
        ]
        for example in examples:
            with self.subTest(example=example):
                self.assertFalse(secret_like(example))
        self.put('auth.py', '\n'.join(examples[:3]))
        run = self.freeze()
        result = run.patch({'auth.js': examples[3]})
        self.assertEqual((Path(result['workspace']) / 'auth.js').read_text(), examples[3])

    def test_literal_credentials_stay_rejected_in_common_formats(self):
        for value in ('token=private-literal-value', 'password="private-literal-value"',
                      '{"access_token":"private-literal-value"}',
                      "{'password': 'private-literal-value'}", 'API_KEY: private-literal-value',
                      'token = "private\\\"literal-value"',
                      '{"token":"synthetic-value", "password":"private-literal-value"}',
                      'password="""private-literal-value"""'):
            with self.subTest(value=value):
                self.assertTrue(secret_like(value))

    def test_collisions_fail_before_publication_and_valid_retry_works(self):
        self.put('existing', 'a file\n')
        self.put('directory/child.txt', 'child\n')
        for files in ({'docs': 'file', 'docs/setup.md': 'child'},
                      {'existing/child.txt': 'child'}, {'directory': 'file'},
                      {'a': 'one', './a': 'two'}):
            with self.subTest(files=list(files)):
                run = self.freeze()
                with self.assertRaises(PolicyError):
                    run.patch(files)
                self.assertEqual(run.state['attempts'], 0)
                self.assertFalse((run.root / 'repair-1').exists())
                result = run.patch({'README.md': 'valid retry\n'})
                self.assertEqual((Path(result['workspace']) / 'README.md').read_text(), 'valid retry\n')

    def test_failed_write_and_diff_preserve_retry_and_prior_evidence(self):
        for failing_operation in ('write', 'diff'):
            with self.subTest(operation=failing_operation):
                run = self.freeze()
                first = run.patch({'README.md': 'first\n'})
                first_diff = Path(first['diff']).read_bytes()
                if failing_operation == 'write':
                    original = Path.open
                    def fail_file(path, mode='r', *args, **kwargs):
                        if path.name == 'README.md' and mode == 'w':
                            with original(path, mode, *args, **kwargs) as stream:
                                stream.write('partial')
                            raise OSError('synthetic partial-write failure')
                        return original(path, mode, *args, **kwargs)
                    fault = patch.object(Path, 'open', fail_file)
                else:
                    fault = patch('initloop.core.subprocess.run', side_effect=OSError('synthetic diff failure'))
                with fault:
                    with self.assertRaises(OSError):
                        run.patch({'README.md': 'failed second\n'})
                self.assertEqual(run.state['attempts'], 1)
                self.assertEqual(Path(first['diff']).read_bytes(), first_diff)
                result = run.patch({'README.md': 'valid second\n'})
                self.assertEqual((Path(result['workspace']) / 'README.md').read_text(), 'valid second\n')
                self.assertEqual(run.state['attempts'], 2)

    def test_publication_and_state_write_failures_roll_back_without_rewriting_history(self):
        for operation in ('publish-file', 'commit-state'):
            with self.subTest(operation=operation):
                run = self.freeze()
                first = run.patch({'README.md': 'first evidence\n'})
                first_bytes = Path(first['diff']).read_bytes()
                if operation == 'publish-file':
                    fault = patch('initloop.core.os.link', side_effect=OSError('synthetic publication failure'))
                else:
                    original = os.replace
                    def fail_state(source, destination):
                        if Path(destination) == run.root / 'state.json':
                            raise OSError('synthetic final-state failure')
                        return original(source, destination)
                    fault = patch('initloop.core.os.replace', side_effect=fail_state)
                with fault:
                    with self.assertRaises(OSError):
                        run.patch({'README.md': 'second draft\n'})
                self.assertEqual(run.state['attempts'], 1)
                self.assertEqual(Run(run.root).state['attempts'], 1)
                self.assertFalse((run.root / 'repair-2').exists())
                self.assertFalse((run.root / 'repair-2.diff').exists())
                self.assertFalse((run.root / 'repair-2.initloop-snapshot.json').exists())
                self.assertEqual(Path(first['diff']).read_bytes(), first_bytes)
                self.assertTrue(list(run.root.glob('repair-failed-*.json')))
                result = Run(run.root).patch({'README.md': 'valid retry\n'})
                self.assertEqual(Path(result['workspace']).name, 'repair-2')

    def test_baseline_mutation_after_repair_blocks_verification(self):
        run = self.freeze([{'name': 'original', 'argv': [sys.executable, 'check.py'],
                            'source': 'frozen synthetic evaluator'}])
        run.patch({'README.md': 'docs\n'})
        (run.root / 'baseline/check.py').write_text('print("tampered")\n')
        with patch.object(NativeBackend, 'execute') as execute:
            with self.assertRaisesRegex(PolicyError, 'baseline'):
                run.verify(NativeBackend())
            execute.assert_not_called()

    def test_orphan_published_artifacts_preserved_and_count_toward_budget(self):
        run = self.freeze()
        (run.root / 'repair-1').mkdir()
        (run.root / 'repair-1/retained.txt').write_text('prior evidence')
        result = run.patch({'README.md': 'retry\n'})
        self.assertEqual(Path(result['workspace']).name, 'repair-2')
        self.assertEqual((run.root / 'repair-1/retained.txt').read_text(), 'prior evidence')
        self.assertEqual(run.state['attempts'], 2)
        run.patch({'README.md': 'last\n'})
        with self.assertRaises(PolicyError):
            run.patch({'README.md': 'over budget\n'})

    def test_redaction_preserves_nonsecret_json_formatting(self):
        text = 'INFO {"count":1,"nested":{"message":"unchanged"}}'
        self.assertEqual(redact(text), text)

    def test_json_fields_and_nested_escaped_json_are_redacted_in_real_native_evidence(self):
        markers = ['synthetic-marker-one-123', 'synthetic-marker-two-456', 'synthetic-marker-three-789', 'synthetic-marker-four-012']
        value = {'password': markers[0], 'nested': [{'access_token': markers[1]}],
                 'payload': json.dumps({'refresh_token': markers[2]}),
                 'escaped': {'pass' + 'word': 'synthetic-marker-four-012'}, 'keep': 'visible'}
        source = json.dumps(value).replace('"password"', '"pass\\u0077ord"', 1)
        for text in (source, 'INFO ' + source, json.dumps(source)):
            with self.subTest(text=text[:12]):
                output = redact(text)
                for marker in markers:
                    self.assertNotIn(marker, output)
                self.assertIn('visible', output)
        self.put('app.py', 'print(' + repr(source) + ')\n')
        run = self.freeze([{'name': 'logs', 'argv': [sys.executable, 'app.py'], 'source': 'synthetic logging contract'}])
        run.patch({'README.md': 'run app\n'})
        result = run.verify(NativeBackend())
        evidence = (run.root / 'verification.json').read_text()
        self.assertEqual(result['status'], 'verified')
        for marker in markers:
            self.assertNotIn(marker, evidence)

    def test_patch_applies_exact_bytes_for_missing_newlines_unicode_and_unusual_paths(self):
        self.put('plain.txt', 'old')
        self.put('space name.txt', 'before\n')
        self.put('unicodé.txt', 'snow ☃\n')
        self.put('tab\tquote".txt', 'before')
        run = self.freeze()
        files = {'plain.txt': 'new', 'space name.txt': 'after', 'unicodé.txt': 'café ☕\n',
                 'tab\tquote".txt': 'after\n', 'new file.txt': 'added without newline',
                 'line\nbreak.txt': 'newline path\n', 'empty.txt': ''}
        result = run.patch(files)
        applied = self.parent / 'applied'
        shutil.copytree(run.root / 'baseline', applied)
        subprocess.run(['git', '-C', str(applied), 'apply', '--check', result['diff']], check=True, capture_output=True)
        subprocess.run(['git', '-C', str(applied), 'apply', result['diff']], check=True, capture_output=True)
        for name, content in files.items():
            self.assertEqual((applied / name).read_bytes(), content.encode())
            self.assertEqual((Path(result['workspace']) / name).read_bytes(), content.encode())

    def test_explicit_executable_entrypoint_is_verified_and_patch_preserves_mode(self):
        run = self.freeze([{'name': 'setup', 'argv': ['./setup.sh'], 'source': 'setup contract', 'contains': ['ready']}])
        result = run.patch({'setup.sh': {'content': '#!/bin/sh\nprintf "ready\\n"\n', 'mode': '0755'}})
        script = Path(result['workspace']) / 'setup.sh'
        self.assertEqual(script.stat().st_mode & 0o777, 0o755)
        self.assertEqual(run.verify(NativeBackend())['status'], 'verified')
        applied = self.parent / 'mode-applied'
        shutil.copytree(run.root / 'baseline', applied)
        subprocess.run(['git', '-C', str(applied), 'apply', result['diff']], check=True, capture_output=True)
        self.assertEqual((applied / 'setup.sh').stat().st_mode & 0o777, 0o755)

    def test_repair_mode_validation_and_text_only_compatibility(self):
        target = self.put('existing.sh', '#!/bin/sh\ntrue\n')
        target.chmod(0o755)
        subprocess.run(['git', '-C', str(self.source), 'add', '--', 'existing.sh'], check=True)
        for entry in ({'content': 'x', 'mode': '0777'}, {'content': 'x', 'mode': 493},
                      {'mode': '0755'}, {'content': 'x', 'mode': '0755', 'other': True}):
            with self.subTest(entry=entry):
                run = self.freeze()
                with self.assertRaises(PolicyError):
                    run.patch({'new.sh': entry})
                self.assertEqual(run.state['attempts'], 0)
        run = self.freeze()
        result = run.patch({'existing.sh': '#!/bin/sh\nprintf ok\n', 'new.sh': 'text only'})
        workspace = Path(result['workspace'])
        self.assertEqual((workspace / 'existing.sh').stat().st_mode & 0o777, 0o755)
        self.assertEqual((workspace / 'new.sh').stat().st_mode & 0o777, 0o644)
        other = self.freeze()
        result = other.patch({'existing.sh': {'content': 'plain text', 'mode': '0644'}})
        self.assertEqual((Path(result['workspace']) / 'existing.sh').stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
