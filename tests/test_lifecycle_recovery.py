"""Owned-process recovery contracts using isolated synthetic services."""
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from initloop.core import PolicyError, write_json
from initloop.lifecycle import Service, identity, serve


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.project = self.root / 'project'
        self.project.mkdir()
        self.service = Service(self.root / 'ledger', 'recovery')
        self.command = [sys.executable, '-u', '-c', 'import time; time.sleep(60)']

    def test_supervisor_loss_blocks_reset_and_duplicate_start_then_recovers_child(self):
        service = self.service
        child = None
        try:
            service.start(self.project, self.command)
            row = json.loads(service.record.read_text())
            child = row['child_pid']
            (service.data / 'retained').write_text('keep')
            os.kill(row['pid'], signal.SIGKILL)
            for _ in range(100):
                if service.status()['status'] != 'running':
                    break
                time.sleep(.02)
            self.assertEqual(service.status()['status'], 'orphaned')
            with self.assertRaises(PolicyError):
                service.reset()
            with self.assertRaises(PolicyError):
                service.start(self.project, self.command)
            self.assertEqual((service.data / 'retained').read_text(), 'keep')
            self.assertEqual(service.stop()['status'], 'stopped')
            self.assertFalse(identity(child), 'recovery must terminate the owned child')
            service.reset()
        finally:
            if child:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_unrecorded_child_launch_is_unknown_and_never_reset_or_signalled(self):
        service = self.service
        service.root.mkdir(parents=True)
        service.data.mkdir()
        (service.data / 'retained').write_text('keep')
        write_json(service.record, {
            'purpose': 'initloop-native-service', 'owner': 'a' * 32,
            'project': str(self.project.resolve()), 'pid': None, 'identity': None,
            'launch_state': 'launching', 'started': False,
        })
        self.assertEqual(service.status()['status'], 'unknown')
        with patch('initloop.lifecycle.os.kill') as kill, patch('initloop.lifecycle.os.killpg') as killpg:
            with self.assertRaises(PolicyError):
                service.stop()
            with self.assertRaises(PolicyError):
                service.reset()
            with self.assertRaises(PolicyError):
                service.start(self.project, self.command)
            kill.assert_not_called()
            killpg.assert_not_called()
        self.assertEqual((service.data / 'retained').read_text(), 'keep')

    def test_child_identity_mismatch_never_signals_reused_pid_or_group(self):
        service = self.service
        service.root.mkdir(parents=True)
        service.data.mkdir()
        write_json(service.record, {
            'purpose': 'initloop-native-service', 'owner': 'a' * 32,
            'project': str(self.project.resolve()), 'pid': None, 'identity': None,
            'launch_state': 'running', 'started': True,
            'child_pid': os.getpid(), 'child_pgid': os.getpgrp(),
            'child_identity': 'unrelated previous process',
        })
        self.assertEqual(service.status()['status'], 'unknown')
        with patch('initloop.lifecycle.os.kill') as kill, patch('initloop.lifecycle.os.killpg') as killpg:
            with self.assertRaises(PolicyError):
                service.stop()
            with self.assertRaises(PolicyError):
                service.reset()
            kill.assert_not_called()
            killpg.assert_not_called()

    def test_child_bookkeeping_failure_cleans_launched_process_before_retry(self):
        service = self.service
        service.root.mkdir(parents=True)
        service.data.mkdir()
        row = {'purpose': 'initloop-native-service', 'owner': 'a' * 32,
               'project': str(self.project.resolve()), 'pid': os.getpid(),
               'identity': identity(os.getpid()), 'argv': self.command,
               'started': False, 'launch_state': 'preparing'}
        write_json(service.record, row)
        import subprocess
        original = subprocess.Popen
        children = []
        failed = False

        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        def fail_first_child_record(path, value):
            nonlocal failed
            if value.get('started') and not failed:
                failed = True
                raise OSError('synthetic bookkeeping failure')
            return write_json(path, value)

        try:
            with patch('initloop.lifecycle.subprocess.Popen', side_effect=capture), \
                    patch('initloop.lifecycle.write_json', side_effect=fail_first_child_record), \
                    patch('initloop.lifecycle.signal.signal'):
                with self.assertRaisesRegex(OSError, 'synthetic bookkeeping failure'):
                    serve(service.record)
            application = next(child for child in children if child.args == self.command)
            self.assertIsNotNone(application.poll(), 'failed bookkeeping must not strand a running child')
            self.assertEqual(service.status()['status'], 'stopped')
            self.assertEqual(service.start(self.project, self.command)['status'], 'running')
            self.assertEqual(service.stop()['status'], 'stopped')
        finally:
            for child in children:
                if child.poll() is None:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()

    def test_supervisor_registration_write_failure_reaps_waiting_supervisor(self):
        service = self.service
        import subprocess
        original = subprocess.Popen
        children = []

        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        def fail_registration(path, value):
            if value.get('pid'):
                raise OSError('synthetic registration failure')
            return write_json(path, value)

        try:
            with patch('initloop.lifecycle.subprocess.Popen', side_effect=capture), \
                    patch('initloop.lifecycle.write_json', side_effect=fail_registration):
                with self.assertRaisesRegex(OSError, 'synthetic registration failure'):
                    service.start(self.project, self.command)
            supervisor = next(child for child in children if 'initloop.lifecycle' in child.args)
            self.assertIsNotNone(supervisor.poll())
            self.assertEqual(service.status()['status'], 'stopped')
            self.assertEqual(service.start(self.project, self.command)['status'], 'running')
            self.assertEqual(service.stop()['status'], 'stopped')
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_recovery_stops_signal_ignoring_descendant_after_leader_exits(self):
        service = self.service
        pid_file = self.project / 'descendant'
        descendant = "import os,signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path('descendant').write_text(str(os.getpid()));time.sleep(60)"
        command = [sys.executable, '-c',
                   'import subprocess,sys,time;subprocess.Popen([sys.executable,"-c",sys.argv[1]]);time.sleep(60)',
                   descendant]
        child = None
        try:
            service.start(self.project, command)
            row = json.loads(service.record.read_text())
            child = row['child_pid']
            for _ in range(100):
                if pid_file.exists():
                    break
                time.sleep(.02)
            self.assertTrue(pid_file.exists())
            os.kill(row['pid'], signal.SIGKILL)
            for _ in range(100):
                if service.status()['status'] == 'orphaned':
                    break
                time.sleep(.02)
            self.assertEqual(service.stop()['status'], 'stopped')
            self.assertFalse(identity(int(pid_file.read_text())))
        finally:
            if child:
                try:
                    os.killpg(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_real_service_logs_redact_nested_and_escaped_json_credentials(self):
        payload = {
            'event': 'harmless-service-event',
            'auth': {'password': 'synthetic-service-password',
                     'access_token': 'synthetic-service-token'},
            'encoded': json.dumps({'nested': {'access_token': 'synthetic-encoded-token'}, 'count': 4}),
            'escaped': r'{"pass\u0077ord":"synthetic-escaped-password","count":7}',
        }
        command = [sys.executable, '-u', '-c',
                   'import json,time;print(json.dumps(' + repr(payload) + '),flush=True);time.sleep(60)']
        try:
            self.service.start(self.project, command)
            for _ in range(100):
                output = self.service.logs()['stdout']
                if 'harmless-service-event' in output:
                    break
                time.sleep(.02)
            self.assertIn('harmless-service-event', output)
            for marker in ('synthetic-service-password', 'synthetic-service-token',
                           'synthetic-encoded-token', 'synthetic-escaped-password'):
                self.assertNotIn(marker, output)
            result = json.loads(output.strip())
            self.assertEqual(result['auth'], {'password': '[REDACTED]', 'access_token': '[REDACTED]'})
            self.assertEqual(json.loads(result['encoded']),
                             {'nested': {'access_token': '[REDACTED]'}, 'count': 4})
            self.assertEqual(json.loads(result['escaped']), {'password': '[REDACTED]', 'count': 7})
        finally:
            self.service.stop()

    def test_supervisor_retains_ownership_and_data_when_group_cleanup_is_unproven(self):
        from unittest.mock import Mock
        service = self.service
        service.root.mkdir(parents=True)
        service.data.mkdir()
        (service.data / 'retained').write_text('keep')
        write_json(service.record, {
            'purpose': 'initloop-native-service', 'owner': 'a' * 32,
            'project': str(self.project), 'pid': 123, 'argv': ['synthetic-command'],
            'started': False, 'launch_state': 'preparing',
        })
        process = Mock(pid=456, returncode=0)
        process.poll.return_value = 0
        with patch('initloop.lifecycle.os.getpid', return_value=123), \
                patch('initloop.lifecycle.signal.signal'), \
                patch('initloop.lifecycle.subprocess.Popen', return_value=process), \
                patch('initloop.lifecycle.process_token', return_value='birth'), \
                patch('initloop.lifecycle.remember_group'), \
                patch('initloop.lifecycle.identity', return_value='identity'), \
                patch('initloop.native.process_token', return_value='birth', create=True), \
                patch('initloop.native.os.getpgid', return_value=456), \
                patch('initloop.native.os.killpg'), \
                patch('initloop.native.group_members', return_value=[789], create=True), \
                patch('initloop.native.time.monotonic', side_effect=[0, 4, 5, 8]), \
                patch('initloop.native.time.sleep'):
            with self.assertRaises(PolicyError):
                serve(service.record)
        row = json.loads(service.record.read_text())
        self.assertEqual(row['child_pgid'], 456)
        self.assertEqual(row['child_identity'], 'birth')
        self.assertEqual(row['launch_state'], 'cleanup-pending')
        with patch.object(service, '_running', return_value=False), \
                patch('initloop.lifecycle.group_members', return_value=[789]), \
                patch('initloop.lifecycle.owned_child', return_value=False):
            self.assertEqual(service.status()['status'], 'unknown')
            with self.assertRaises(PolicyError):
                service.reset()
            with self.assertRaises(PolicyError):
                service.start(self.project, self.command)
            with self.assertRaises(PolicyError):
                service.stop()
        self.assertEqual((service.data / 'retained').read_text(), 'keep')

    def test_retained_descendant_birth_identity_can_recover_after_leader_exit(self):
        from initloop.lifecycle import owned_group
        row = {'child_pid': 456, 'child_pgid': 456, 'child_identity': 'old-leader',
               'group_identities': {'789': 'descendant-birth'}}
        with patch('initloop.lifecycle.owned_child', return_value=False), \
                patch('initloop.lifecycle.group_members', return_value=[789]), \
                patch('initloop.lifecycle.process_token', return_value='descendant-birth'), \
                patch('initloop.lifecycle.os.getpgid', return_value=456):
            self.assertTrue(owned_group(row))
        with patch('initloop.lifecycle.owned_child', return_value=False), \
                patch('initloop.lifecycle.group_members', return_value=[789]), \
                patch('initloop.lifecycle.process_token', return_value='reused-birth'), \
                patch('initloop.lifecycle.os.killpg') as signals:
            self.assertFalse(owned_group(row))
            with self.assertRaisesRegex(PolicyError, 'identity'):
                self.service._stop_orphan(row)
            signals.assert_not_called()
