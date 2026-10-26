from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from initloop.backend import DockerBackend
from initloop.core import PolicyError

class CleanupTests(unittest.TestCase):
    def test_unregistered_directory_is_rejected_before_docker_access(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('initloop.backend.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','')) as call:
                with self.assertRaises(PolicyError): DockerBackend().execute(Path(directory),'python:3',['true'])
            call.assert_not_called()

    def test_cleanup_checks_exact_ownership_and_preserves_other_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger=Path(directory)
            name='initloop-'+'a'*32
            (ledger/(name+'.json')).write_text(json.dumps({'name':name,'owner':'b'*32}))
            calls=[]
            def command(argv,**kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv,0,'not-our-owner\n','')
            with patch('initloop.backend.subprocess.run',side_effect=command):
                result=DockerBackend(ledger).cleanup()
            self.assertEqual(result[0]['status'],'ownership-mismatch')
            self.assertFalse(any('rm' in argv for argv in calls))
            self.assertTrue((ledger/(name+'.json')).exists())

    def test_cleanup_removes_only_recorded_owned_container(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger=Path(directory); name='initloop-'+'a'*32; owner='b'*32
            (ledger/(name+'.json')).write_text(json.dumps({'name':name,'owner':owner}))
            calls=[]
            def command(argv,**kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv,0,owner+'\n','')
            with patch('initloop.backend.subprocess.run',side_effect=command):
                result=DockerBackend(ledger).cleanup()
            self.assertEqual(result[0]['status'],'removed')
            self.assertIn(['docker','rm','-f',name],calls)
            self.assertFalse((ledger/(name+'.json')).exists())

if __name__=='__main__': unittest.main()
