"""CLI error boundaries, exit statuses, and dispatch argument contracts."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest
from unittest.mock import patch

from initloop.cli import main
from initloop.core import PolicyError


class CLITests(unittest.TestCase):
    def invoke(self, argv):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(argv)
        return code, json.loads(stdout.getvalue() or stderr.getvalue())

    def test_docker_requires_image_before_any_backend_is_created(self):
        for command in ('execute', 'baseline', 'verify'):
            with self.subTest(command=command), patch('initloop.cli.DockerBackend') as backend:
                code, row = self.invoke([command, 'workspace'])
                self.assertEqual(code, 2)
                self.assertEqual(row['status'], 'blocked')
                self.assertIn('--image', row['error'])
                backend.assert_not_called()

    def test_native_execute_strips_separator_and_maps_failed_command_to_exit_one(self):
        with patch('initloop.cli.NativeBackend') as backend:
            backend.return_value.execute.return_value = {'exit_code': 3, 'stdout': 'failed'}
            code, row = self.invoke(['execute', '--runner', 'native', '--timeout', '12', 'workspace', '--', 'python', 'app.py'])
            self.assertEqual(code, 1)
            self.assertEqual(row['exit_code'], 3)
            backend.return_value.execute.assert_called_once_with(Path('workspace'), None, ['python', 'app.py'], 12)

    def test_execute_uses_remainder_without_separator(self):
        with patch('initloop.cli.DockerBackend') as backend:
            backend.return_value.execute.return_value = {'exit_code': 0}
            code, _ = self.invoke(['execute', '--image', 'trusted:image', 'workspace', 'python', 'app.py'])
            self.assertEqual(code, 0)
            backend.return_value.execute.assert_called_once_with(Path('workspace'), 'trusted:image', ['python', 'app.py'], 60)

    def test_report_and_cancel_use_persisted_run(self):
        with patch('initloop.cli.Run') as run:
            run.return_value.report.return_value = {'status': 'cancelled'}
            for command in ('report', 'cancel'):
                self.assertEqual(self.invoke([command, 'run'])[0], 0)
            run.return_value.transition.assert_called_once_with('cancelled')
            self.assertEqual(run.return_value.report.call_count, 2)

    def test_verify_only_returns_success_for_verified(self):
        with patch('initloop.cli.Run') as run, patch('initloop.cli.NativeBackend'):
            for status in ('partial', 'failed', 'verified'):
                with self.subTest(status=status):
                    run.return_value.verify.return_value = {'status': status}
                    self.assertEqual(self.invoke(['verify', 'run', '--runner', 'native'])[0], 0 if status == 'verified' else 1)

    def test_baseline_preserves_frozen_check_names_timeout_and_records_results(self):
        with patch('initloop.cli.Run') as run, patch('initloop.cli.DockerBackend') as backend:
            run.return_value.root = Path('run')
            run.return_value.state = 'baselining'
            run.return_value.check_contract.return_value = {'checks': [
                {'name': 'first', 'argv': ['first'], 'timeout': 5}, {'name': 'second', 'argv': ['second']}]}
            backend.return_value.execute.return_value = {'exit_code': 1}
            code, row = self.invoke(['baseline', 'run', '--image', 'trusted:image'])
            self.assertEqual(code, 0)  # Baseline failures are evidence, not repair success.
            self.assertEqual([r['name'] for r in row['results']], ['first', 'second'])
            self.assertEqual(backend.return_value.execute.call_args_list[0].args, (Path('run/baseline'), 'trusted:image', ['first'], 5))
            self.assertEqual(backend.return_value.execute.call_args_list[1].args[-1], 60)
            run.return_value.record_baseline.assert_called_once_with(row['results'])

    def test_begin_and_repair_read_json_inputs_without_changing_the_mapping(self):
        with tempfile.TemporaryDirectory() as temporary, patch('initloop.cli.Run') as run:
            path = Path(temporary) / 'input.json'
            contract = {'objective': 'synthetic', 'checks': []}
            path.write_text(json.dumps(contract))
            run.create.return_value.root = Path('runs/new')
            run.create.return_value.state = {'status': 'created'}
            self.assertEqual(self.invoke(['begin', 'project', '--runs', 'runs', '--contract', str(path), '--include-dirty'])[0], 0)
            run.create.assert_called_once_with(Path('project'), Path('runs'), contract, True)
            mapping = {'setup.sh': {'content': '#!/bin/sh\n', 'mode': '0755'}}
            path.write_text(json.dumps(mapping))
            run.return_value.patch.return_value = {'status': 'repaired'}
            self.assertEqual(self.invoke(['repair', 'run', '--files', str(path)])[0], 0)
            run.return_value.patch.assert_called_once_with(mapping)

    def test_invalid_json_and_missing_input_are_blocked_machine_readably(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'invalid.json'
            path.write_text('{')
            for target in (path, path.with_name('absent.json')):
                code, row = self.invoke(['repair', 'run', '--files', str(target)])
                self.assertEqual(code, 2)
                self.assertEqual(row['status'], 'blocked')

    def test_cleanup_exit_status_requires_every_resource_removed(self):
        with patch('initloop.cli.DockerBackend') as backend:
            for rows, expected in (([], 0), ([{'status': 'removed'}], 0), ([{'status': 'ownership-mismatch'}], 1)):
                backend.return_value.cleanup.return_value = rows
                self.assertEqual(self.invoke(['cleanup', '--ledger', 'ledger'])[0], expected)
            backend.assert_called_with(Path('ledger'))

    def test_workflow_dispatch_keeps_requested_mode_and_selected_paths(self):
        with patch('initloop.workflow.audit', return_value={'static': True}) as audit:
            self.assertEqual(self.invoke(['workflow', 'project'])[0], 0)
            audit.assert_called_once_with(Path('project'))
        with patch('initloop.workflow.propose', return_value={'proposed': True}) as propose:
            self.assertEqual(self.invoke(['workflow', 'project', '--destination', 'out', '--mode', 'replace', '--select', 'AGENTS.md'])[0], 0)
            propose.assert_called_once_with(Path('project'), Path('out'), 'replace', ['AGENTS.md'])

    def test_refresh_and_audit_dispatch(self):
        with patch('initloop.workflow.refresh', return_value={'status': 'stale'}) as refresh:
            self.assertEqual(self.invoke(['refresh', 'project', '--manifest', 'manifest.json'])[0], 0)
            refresh.assert_called_once_with(Path('project'), Path('manifest.json'))
        with patch('initloop.cli.Inventory') as inventory:
            inventory.return_value.scan.return_value = {'files': []}
            self.assertEqual(self.invoke(['audit', 'project'])[0], 0)
            inventory.return_value.scan.assert_called_once_with()

    def test_dev_requires_project_and_forwards_only_explicit_command(self):
        with patch('initloop.lifecycle.Service') as service:
            code, row = self.invoke(['dev', 'start', '--ledger', 'ledger', '--name', 'app'])
            self.assertEqual(code, 2)
            self.assertIn('--project', row['error'])
            service.return_value.start.assert_not_called()
            service.return_value.start.return_value = {'status': 'running'}
            self.assertEqual(self.invoke(['dev', 'start', '--ledger', 'ledger', '--name', 'app', '--project', 'project', '--', 'python', 'app.py', '--port', '8000'])[0], 0)
            service.return_value.start.assert_called_once_with(Path('project'), ['python', 'app.py', '--port', '8000'])
            service.return_value.status.return_value = {'status': 'stopped'}
            self.assertEqual(self.invoke(['dev', 'status', '--ledger', 'ledger', '--name', 'app'])[0], 0)
            service.return_value.status.assert_called_once_with()

    def test_blocked_errors_redact_credentials_and_preserve_exit_contract(self):
        for error in (PolicyError('password=synthetic-marker'), ValueError('bad input'), OSError('missing'), subprocess.SubprocessError('command failed')):
            with self.subTest(error=type(error).__name__), patch('initloop.cli.Inventory', side_effect=error):
                code, row = self.invoke(['audit', 'project'])
                self.assertEqual(code, 2)
                self.assertEqual(row['status'], 'blocked')
                self.assertNotIn('synthetic-marker', row['error'])

    def test_module_entrypoint_returns_machine_readable_blocked_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / 'absent'
            completed = subprocess.run([sys.executable, '-m', 'initloop.cli', 'execute',
                                        '--runner', 'native', str(missing), '--', 'python', 'app.py'],
                                       capture_output=True, text=True)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(completed.stdout, '')
            self.assertEqual(json.loads(completed.stderr)['status'], 'blocked')

    def test_default_sys_argv_and_argument_parser_failure(self):
        with patch('sys.argv', ['initloop', 'audit', 'project']), patch('initloop.cli.Inventory') as inventory:
            inventory.return_value.scan.return_value = {}
            self.assertEqual(self.invoke(None)[0], 0)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(['unknown-command'])
        self.assertEqual(raised.exception.code, 2)
