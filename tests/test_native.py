import os
from pathlib import Path
import sys
import tempfile
import unittest
from initloop.core import _register_snapshot
from initloop.native import NativeBackend

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
