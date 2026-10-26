from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from initloop.core import PolicyError, Run
from initloop.backend import DockerBackend


class RecordedBackend:
    def __init__(self, code=0): self.calls=[]; self.code=code
    def execute(self, workspace, image, argv, timeout=60):
        self.calls.append((workspace,image,argv,timeout))
        return {'exit_code':self.code,'stdout':'record=42','outcome':'completed'}


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'project'; self.root.mkdir()
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        (self.root/'test.py').write_text('assert True')
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
        self.contract={'objective':'record','protected_paths':['test.py'],'checks':[{'name':'record','argv':['python','test.py'],'source':'test.py','contains':['record=42']}]}
        self.run=Run.create(self.root,Path(self.tmp.name)/'runs',self.contract)
        self.run.record_baseline([{'exit_code':1}])

    def test_protected_assertion_cannot_be_repaired(self):
        for name in ['test.py','./test.py']:
            with self.assertRaises(PolicyError): self.run.patch({name:'pass'})

    def test_directory_protection_covers_descendants(self):
        self.run.contract_path.chmod(0o600)
        # A new independently frozen run, not mutation of this run's contract.
        contract=dict(self.contract,protected_paths=['tests'])
        other=Run.create(self.root,Path(self.tmp.name)/'other-runs',contract)
        other.record_baseline([])
        with self.assertRaises(PolicyError): other.patch({'tests/new.py':'pass'})

    def test_twice_success_and_resume_preserve_exact_snapshot(self):
        self.run.patch({'README.md':'Run python test.py\n'})
        backend=RecordedBackend()
        result=Run(self.run.root).verify(backend,'local-image')
        self.assertEqual(result['status'],'verified')
        self.assertEqual(len(backend.calls),2)
        self.assertEqual(Run(self.run.root).state['phase'],'verified')
        self.assertEqual((self.root/'test.py').read_text(),'assert True')

    def test_failed_checks_remain_partial_and_budget_is_bounded(self):
        for attempt in range(3):
            self.run.patch({'README.md':str(attempt)})
            self.assertEqual(self.run.verify(RecordedBackend(1),'local-image')['status'],'partial')
        with self.assertRaises(PolicyError): self.run.patch({'README.md':'fourth'})

    def test_changed_snapshot_never_runs(self):
        repair=self.run.patch({'README.md':'hello'})
        (Path(repair['workspace'])/'test.py').write_text('pass')
        backend=RecordedBackend()
        with self.assertRaises(PolicyError): self.run.verify(backend,'local-image')
        self.assertEqual(backend.calls,[])

    def test_cancelled_run_cannot_resume_mutation(self):
        self.run.transition('cancelled')
        with self.assertRaises(PolicyError): Run(self.run.root).patch({'README.md':'hello'})

    def test_docker_unavailable_has_no_host_fallback(self):
        with patch('initloop.backend.subprocess.run',return_value=subprocess.CompletedProcess([],1,'','unavailable')):
            with self.assertRaises(PolicyError): DockerBackend().execute(self.root,'python:3',['python','test.py'])

    def test_runtime_budget_and_image_injection(self):
        with self.assertRaises(PolicyError): DockerBackend().execute(self.root,'image',['python'],timeout=999)
        with self.assertRaises(PolicyError): DockerBackend().command(self.root,'--privileged',['true'],'name')

    def test_timeout_is_failure_even_when_exit_code_matches(self):
        self.run.patch({'README.md':'hello'})
        class TimeoutBackend:
            def execute(self,*args,**kwargs): return {'exit_code':0,'outcome':'timeout','stdout':'record=42'}
        self.assertEqual(self.run.verify(TimeoutBackend(),'image')['status'],'partial')

    def test_local_service_url_is_valid_repair(self):
        result=self.run.patch({'README.md':'Open http://127.0.0.1:8000\n'})
        self.assertIn('127.0.0.1',(Path(result['workspace'])/'README.md').read_text())

    def test_explicit_synthetic_service_auth_is_valid_but_real_token_is_not(self):
        self.run.patch({'README.md':'Local service uses Authorization: Bearer synthetic-token\n'})
        other=Run.create(self.root,Path(self.tmp.name)/'other',self.contract)
        other.record_baseline([])
        with self.assertRaises(PolicyError): other.patch({'README.md':'Authorization: Bearer live_abcdefghijklmnopqrst\n'})

    def test_malformed_actions_and_contracts_fail_as_policy_errors(self):
        for checks in [[1],[{'name':'bad','argv':['true'],'source':'objective','timeout':-1}]]:
            with self.assertRaises(PolicyError): Run.create(self.root,Path(self.tmp.name)/'invalid',{'objective':'x','checks':checks})
        with self.assertRaises(PolicyError): self.run.patch(['not-a-file-map'])

    def test_revising_unverified_draft_preserves_history_and_budget(self):
        first=self.run.patch({'README.md':'draft one'})
        second=self.run.patch({'README.md':'draft two'})
        self.assertNotEqual(first['workspace'],second['workspace'])
        self.assertEqual((Path(first['workspace'])/'README.md').read_text(),'draft one')
        self.assertEqual((Path(second['workspace'])/'README.md').read_text(),'draft two')
        self.run.patch({'README.md':'draft three'})
        with self.assertRaises(PolicyError): self.run.patch({'README.md':'fourth'})

if __name__=='__main__': unittest.main()
