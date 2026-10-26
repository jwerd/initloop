"""Opt-in actual runtime boundary checks; never silently counted when Docker is absent."""
import os
from pathlib import Path
import tempfile
import unittest
from initloop.backend import DockerBackend
from initloop.core import _register_snapshot, PolicyError


@unittest.skipUnless(os.environ.get('INITLOOP_DOCKER_IMAGE'), 'live Docker checks require explicit INITLOOP_DOCKER_IMAGE')
class DockerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.source=Path(self.tmp.name)/'snapshot'; self.source.mkdir(mode=0o755)
        (self.source/'input.txt').write_text('unchanged')
        _register_snapshot(self.source)
        self.backend=DockerBackend(Path(self.tmp.name)/'resources')
        self.image=os.environ['INITLOOP_DOCKER_IMAGE']

    def test_real_runtime_identity_egress_secret_and_input_boundary(self):
        # Synthetic sentinel only; no real credential is collected or forwarded.
        old=os.environ.get('INITLOOP_PARENT_SECRET')
        os.environ['INITLOOP_PARENT_SECRET']='synthetic-parent-only'
        self.addCleanup(lambda: os.environ.pop('INITLOOP_PARENT_SECRET',None) if old is None else os.environ.__setitem__('INITLOOP_PARENT_SECRET',old))
        code='''import os,pathlib,socket
assert os.getuid()==65534
assert "INITLOOP_PARENT_SECRET" not in os.environ
assert not pathlib.Path("/var/run/docker.sock").exists()
try: pathlib.Path("/input/input.txt").write_text("changed")
except OSError: pass
else: raise AssertionError("input writable")
s=socket.socket(); s.settimeout(1); assert s.connect_ex(("1.1.1.1",443))!=0
pathlib.Path("/workspace/local.txt").write_text("disposable")
print("unprivileged; input read-only; no inherited secret/socket; egress blocked")
'''
        result=self.backend.execute(self.source,self.image,['python','-c',code],20)
        self.assertEqual(result['exit_code'],0,result)
        self.assertEqual(result['cleanup'],'removed')
        self.assertEqual((self.source/'input.txt').read_text(),'unchanged')
        self.assertFalse((self.source/'local.txt').exists())

    def test_actual_timeout_is_cleaned_and_classified(self):
        result=self.backend.execute(self.source,self.image,['python','-c','import time; time.sleep(30)'],2)
        self.assertEqual(result['outcome'],'timeout',result)
        self.assertEqual(result['exit_code'],124)
        self.assertEqual(result['cleanup'],'removed')

    def test_changed_input_refused_before_container_launch(self):
        (self.source/'input.txt').write_text('changed after controller freeze')
        with self.assertRaises(PolicyError): self.backend.execute(self.source,self.image,['true'])

    def test_project_generated_executables_can_run_in_workspace(self):
        code="from pathlib import Path; import subprocess; p=Path('/workspace/probe'); p.write_text(" + repr("#!/bin/sh\nexit 0\n") + "); p.chmod(0o700); subprocess.run([str(p)],check=True)"
        result=self.backend.execute(self.source,self.image,['python','-c',code],20)
        self.assertEqual(result['exit_code'],0,result)
        self.assertEqual(result['cleanup'],'removed')

    def test_output_limit_and_fresh_filesystem(self):
        result=self.backend.execute(self.source,self.image,['python','-c','print("x"*1200000)'],20)
        self.assertEqual(result['outcome'],'output-limit',result)
        self.assertEqual(result['cleanup'],'removed')
        again=self.backend.execute(self.source,self.image,['python','-c','from pathlib import Path; assert not Path("/workspace/local.txt").exists(); print("fresh")'],20)
        self.assertEqual(again['exit_code'],0,again)

if __name__=='__main__': unittest.main()
