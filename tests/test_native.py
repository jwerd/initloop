import os
from pathlib import Path
import sys
import tempfile
import unittest
from initloop.core import _register_snapshot
from initloop.native import NativeBackend, terminate_group
from initloop.core import PolicyError
from unittest.mock import Mock, patch

class NativeTests(unittest.TestCase):
    def test_native_is_explicit_disposable_and_not_sandboxed(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input';p.mkdir();(p/'input.txt').write_text('original');_register_snapshot(p)
            result=NativeBackend().execute(p,None,[sys.executable,'-c',"from pathlib import Path; Path('input.txt').write_text('changed'); print('native-ok')"])
            self.assertEqual(result['exit_code'],0,result)
            self.assertIn('native-ok',result['stdout'])
            self.assertEqual((p/'input.txt').read_text(),'original')
            self.assertFalse(result['sandboxed'])
            self.assertEqual(result['network'],'host; unrestricted by helper')
    def test_timeout_cleans_group_and_does_not_forward_credentials(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input';p.mkdir();_register_snapshot(p)
            os.environ['INITLOOP_PARENT_SECRET']='private-sentinel'
            try:
                r=NativeBackend().execute(p,None,[sys.executable,'-c',"import os,time; assert 'INITLOOP_PARENT_SECRET' not in os.environ; time.sleep(10)"],1)
            finally:os.environ.pop('INITLOOP_PARENT_SECRET',None)
            self.assertEqual(r['outcome'],'timeout',r)
            self.assertEqual(r['cleanup'],'removed')

    def test_exited_leader_does_not_leave_signal_ignoring_child(self):
        import signal
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'input';p.mkdir();_register_snapshot(p);marker=Path(t)/'child.pid'
            child="import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path("+repr(str(marker))+").write_text(str(os.getpid())); time.sleep(60)"
            parent="import subprocess,time; from pathlib import Path; subprocess.Popen("+repr([sys.executable,'-c',child])+"); p=Path("+repr(str(marker))+");\nwhile not p.exists(): time.sleep(.01)\nprint('leader-done')"
            try:
                result=NativeBackend().execute(p,None,[sys.executable,'-c',parent],5)
                pid=int(marker.read_text());state=subprocess.run(['/bin/ps','-p',str(pid),'-o','stat='],capture_output=True,text=True).stdout.strip()
                self.assertTrue(not state or state.startswith('Z'),(state,result))
            finally:
                if marker.exists():
                    try:os.kill(int(marker.read_text()),signal.SIGKILL)
                    except ProcessLookupError:pass


class CleanupProofTests(unittest.TestCase):
    def process(self):
        process = Mock(pid=456, returncode=0)
        process.poll.return_value = 0
        return process

    def test_kill_waits_for_live_descendants_after_leader_exit(self):
        process = self.process()
        with patch('initloop.native.group_members', side_effect=[[789], [789], [789], [789], []]) as members, \
                patch('initloop.native.process_token', return_value='birth'), \
                patch('initloop.native.os.getpgid', return_value=456), \
                patch('initloop.native.os.killpg') as signals, \
                patch('initloop.native.time.monotonic', side_effect=[0, 4, 5, 5, 5]), \
                patch('initloop.native.time.sleep'):
            terminate_group(process, {'456': 'birth', '789': 'birth'})
        self.assertGreaterEqual(members.call_count, 5)
        self.assertEqual(signals.call_args_list[-1].args[1], __import__('signal').SIGKILL)

    def test_persistent_group_is_unresolved(self):
        with patch('initloop.native.group_members', return_value=[789]), \
                patch('initloop.native.process_token', return_value='birth'), \
                patch('initloop.native.os.getpgid', return_value=456), \
                patch('initloop.native.os.killpg'), \
                patch('initloop.native.time.monotonic', side_effect=[0, 4, 5, 8]), \
                patch('initloop.native.time.sleep'):
            with self.assertRaisesRegex(PolicyError, 'cleanup'):
                terminate_group(self.process(), {'789': 'birth'})

    def test_reused_group_never_signalled(self):
        with patch('initloop.native.group_members', return_value=[789]), \
                patch('initloop.native.process_token', return_value='new-birth'), \
                patch('initloop.native.os.getpgid', return_value=456), \
                patch('initloop.native.os.killpg') as signals:
            with self.assertRaisesRegex(PolicyError, 'ownership'):
                terminate_group(self.process(), {'789': 'old-birth'})
            signals.assert_not_called()

    def test_unresolved_execution_preserves_exact_work_and_recovery_record(self):
        import json
        import shutil
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / 'input'
            source.mkdir()
            _register_snapshot(source)
            retained = None
            try:
                with patch('initloop.native.terminate_group', side_effect=PolicyError('cleanup pending')):
                    result = NativeBackend().execute(source, None, [sys.executable, '-c', "from pathlib import Path; Path('proof').write_text('keep')"])
                self.assertEqual(result['cleanup'], 'retained')
                self.assertEqual(result['outcome'], 'cleanup-pending')
                retained = Path(result['retained_work'])
                self.assertEqual((retained / 'proof').read_text(), 'keep')
                recovery = json.loads(Path(result['recovery_record']).read_text())
                self.assertEqual(recovery['working_copy'], str(retained))
                self.assertGreater(recovery['child_pgid'], 1)
                self.assertTrue(recovery['child_identity'])
                self.assertIn('manual', result['recovery'])
            finally:
                if retained:
                    shutil.rmtree(retained.parent)

    def test_permission_failure_requires_independent_absence_proof(self):
        for remaining in ([], [789]):
            with self.subTest(remaining=remaining), \
                    patch('initloop.native.group_members', side_effect=[[789], remaining] + [remaining] * 4), \
                    patch('initloop.native.process_token', return_value='birth'), \
                    patch('initloop.native.os.getpgid', return_value=456), \
                    patch('initloop.native.os.killpg', side_effect=PermissionError), \
                    patch('initloop.native.time.sleep'):
                if remaining:
                    with self.assertRaisesRegex(PolicyError, 'permission'):
                        terminate_group(self.process(), {'789': 'birth'})
                else:
                    terminate_group(self.process(), {'789': 'birth'})

    def test_inspection_failure_and_recovery_write_failure_preserve_work(self):
        import shutil
        for write_failure in (False, True):
            with self.subTest(write_failure=write_failure), tempfile.TemporaryDirectory() as t:
                source = Path(t) / 'input'
                source.mkdir()
                _register_snapshot(source)
                retained = Path(t) / 'retained'
                retained.mkdir()
                process = self.process()
                from initloop.core import write_json
                def save_record(path, row):
                    if write_failure and row.get('cleanup_error') == 'cannot inspect group':
                        raise OSError('record failure')
                    return write_json(path, row)
                with patch('initloop.native.tempfile.mkdtemp', return_value=str(retained)), \
                        patch('initloop.native.subprocess.Popen', return_value=process), \
                        patch('initloop.native.process_token', return_value='birth'), \
                        patch('initloop.native.remember_group', side_effect=PolicyError('cannot inspect group')), \
                        patch('initloop.native.group_members', side_effect=PolicyError('cannot inspect group')), \
                        patch('initloop.native.write_json', side_effect=save_record):
                    with self.assertRaisesRegex(PolicyError, str(retained)):
                        NativeBackend().execute(source, None, ['synthetic-command'])
                self.assertTrue((retained / 'project').is_dir())
                self.assertTrue((retained / 'recovery.json').exists())

    def test_successful_execution_removes_disposable_work(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / 'input'
            source.mkdir()
            _register_snapshot(source)
            retained = Path(t) / 'work'
            retained.mkdir()
            with patch('initloop.native.tempfile.mkdtemp', return_value=str(retained)):
                result = NativeBackend().execute(source, None, [sys.executable, '-c', 'pass'])
            self.assertEqual(result['cleanup'], 'removed')
            self.assertFalse(retained.exists())

    def test_zombie_members_are_not_live_cleanup_blockers(self):
        from initloop.process_groups import group_members
        result = Mock(returncode=0, stdout='456 456 Z\n789 456 S\n800 999 S\n')
        with patch('initloop.process_groups.subprocess.run', return_value=result):
            self.assertEqual(group_members(456), [789])


    def test_cleanup_interruption_keeps_work_and_reports_recovery_paths(self):
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / 'input'
            source.mkdir()
            _register_snapshot(source)
            retained = Path(t) / 'work'
            retained.mkdir()
            process = self.process()
            with patch('initloop.native.tempfile.mkdtemp', return_value=str(retained)), \
                    patch('initloop.native.subprocess.Popen', return_value=process), \
                    patch('initloop.native.process_token', return_value='birth'), \
                    patch('initloop.native.remember_group'), \
                    patch('initloop.native.terminate_group', side_effect=KeyboardInterrupt):
                with self.assertRaisesRegex(PolicyError, str(retained)) as raised:
                    NativeBackend().execute(source, None, ['synthetic-command'])
            self.assertIn(str(retained / 'recovery.json'), str(raised.exception))
            self.assertTrue((retained / 'project').is_dir())
            self.assertTrue((retained / 'recovery.json').is_file())


    def test_interrupted_launch_preserves_unknown_ownership_and_work(self):
        import json
        with tempfile.TemporaryDirectory() as t:
            source = Path(t) / 'input'
            source.mkdir()
            _register_snapshot(source)
            retained = Path(t) / 'work'
            retained.mkdir()
            with patch('initloop.native.tempfile.mkdtemp', return_value=str(retained)), \
                    patch('initloop.native.subprocess.Popen', side_effect=KeyboardInterrupt), \
                    patch('initloop.native.os.killpg') as signals:
                with self.assertRaisesRegex(PolicyError, str(retained)):
                    NativeBackend().execute(source, None, ['synthetic-command'])
            self.assertTrue((retained / 'project').is_dir())
            record = json.loads((retained / 'recovery.json').read_text())
            self.assertEqual(record['launch_state'], 'unknown')
            self.assertIsNone(record['child_pgid'])
            self.assertEqual(record['working_copy'], str(retained / 'project'))
            signals.assert_not_called()
