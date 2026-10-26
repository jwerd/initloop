import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from initloop.lifecycle import Service
from initloop.core import PolicyError

class LifecycleTests(unittest.TestCase):
    def test_owned_foreground_lifecycle_and_data_survive_restart(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t); project=root/'project';project.mkdir();s=Service(root/'ledger','example')
            command=[sys.executable,'-u','-c',"import os,time; from pathlib import Path; p=Path(os.environ['INITLOOP_DATA_DIR'])/'n'; n=int(p.read_text())+1 if p.exists() else 1; p.write_text(str(n)); print('started',n,flush=True); time.sleep(60)"]
            try:
                r=s.start(project,command);self.assertEqual(r['status'],'running')
                for _ in range(50):
                    if 'started 1' in s.logs()['stdout']:break
                    time.sleep(.05)
                self.assertIn('started 1',s.logs()['stdout'])
                with self.assertRaises(PolicyError):s.reset()
                with self.assertRaises(PolicyError):s.start(project,command)
                self.assertEqual(s.stop()['status'],'stopped')
                s.start(project,command)
                for _ in range(50):
                    if 'started 2' in s.logs()['stdout']:break
                    time.sleep(.05)
                self.assertIn('started 2',s.logs()['stdout'])
                s.stop();self.assertEqual(s.reset()['status'],'reset')
                self.assertEqual(list((root/'ledger/example/data').iterdir()),[])
            finally:s.stop()
    def test_unowned_directory_reset_and_nested_ledger_refused(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'project').mkdir()
            with self.assertRaises(PolicyError):Service(p/'project/ledger','x').start(p/'project',['true'])
            s=Service(p/'ledger','x');s.root.mkdir(parents=True);(s.root/'valuable').write_text('keep')
            with self.assertRaises(PolicyError):s.reset()
            self.assertEqual((s.root/'valuable').read_text(),'keep')

    def test_symlink_lock_and_logs_never_write_unrelated_files(self):
        from initloop.core import write_json
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);project=p/'project';project.mkdir();valuable=p/'valuable';valuable.write_text('keep')
            s=Service(p/'ledger','x');s.ledger.mkdir()
            lock=s.ledger/'x.lock';lock.symlink_to(valuable)
            try:
                with self.assertRaises(PolicyError):s.start(project,[sys.executable,'-c','print(1)'])
                self.assertEqual(valuable.read_text(),'keep')
            finally:
                if s.record.exists():s.stop()
            lock.unlink()
            s.root.mkdir(exist_ok=True)
            write_json(s.record,{'purpose':'initloop-native-service','owner':'a'*32,'project':str(project.resolve()),'pid':None,'identity':None})
            for name in ('supervisor.log','service.log'):
                link=s.root/name;link.symlink_to(valuable)
                try:
                    with self.assertRaises(PolicyError):s.start(project,[sys.executable,'-c','print(1)'])
                    self.assertEqual(valuable.read_text(),'keep')
                finally:link.unlink()

    def test_stop_serializes_with_pending_start(self):
        import subprocess
        import threading
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);project=p/'project';project.mkdir();s=Service(p/'ledger','x')
            pending=threading.Event();release=threading.Event();stopped=threading.Event();errors=[]
            original=subprocess.Popen
            def paused(*args,**kwargs):
                pending.set();release.wait(5);return original(*args,**kwargs)
            def start():
                try:s.start(project,[sys.executable,'-c','import time;time.sleep(60)'])
                except Exception as e:errors.append(e)
            def stop():
                try:s.stop()
                except Exception as e:errors.append(e)
                finally:stopped.set()
            with patch('initloop.lifecycle.subprocess.Popen',side_effect=paused):
                a=threading.Thread(target=start);a.start();self.assertTrue(pending.wait(2))
                b=threading.Thread(target=stop);b.start();time.sleep(.1)
                was_stopped=stopped.is_set();release.set();a.join(5);b.join(5)
            try:
                self.assertFalse(was_stopped,'stop must wait for start ownership initialization')
                self.assertFalse(errors,errors)
                self.assertEqual(s.status()['status'],'stopped')
            finally:s.stop()

    def test_slow_supervisor_is_owned_and_starting_not_stopped(self):
        import subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);project=p/'project';project.mkdir();s=Service(p/'ledger','slow')
            original=subprocess.Popen; launched=[]
            def delayed(argv,*args,**kwargs):
                if '-m' in argv and 'initloop.lifecycle' in argv:
                    process=original([sys.executable,'-c','import time;time.sleep(60)','-m','initloop.lifecycle','_serve',str(s.record)],*args,**kwargs)
                    launched.append(process);return process
                return original(argv,*args,**kwargs)
            with patch('initloop.lifecycle.subprocess.Popen',side_effect=delayed):
                try:
                    self.assertEqual(s.start(project,['true'])['status'],'starting')
                    self.assertEqual(s.status()['status'],'starting')
                    with self.assertRaises(PolicyError):s.reset()
                    with self.assertRaises(PolicyError):s.start(project,['true'])
                finally:
                    s.stop()
                    for process in launched:
                        if process.poll() is None:process.terminate()
                        process.wait()
