"""Static evidence points at raw artifacts without certifying their semantics."""
import json
import unittest

from initloop.repository_evidence import discover_repository


class RepositoryEvidenceTests(unittest.TestCase):
    def discover(self, **files):
        return discover_repository({name:text.encode() for name,text in files.items()})

    def test_unconventional_literal_paths_follow_existing_root_and_source_candidates(self):
        report=self.discover(**{'nested/tool.py':'from pathlib import Path\nPath("../attic/moves.sql")\nPath("weird/api.json")\n', 'attic/moves.sql':'create table demo(id int);','weird/api.json':'{}'})
        refs=report['references']
        self.assertTrue(any(r['source']=='nested/tool.py' and r['line']==2 and any(c['path']=='attic/moves.sql' and c['exists'] for c in r['candidates']) for r in refs))
        self.assertTrue(any(any(c['path']=='weird/api.json' and c['exists'] for c in r['candidates']) for r in refs))
        self.assertTrue(all(r['state']=='declared' and r['runtime_verified'] is False for r in refs))
        self.assertTrue(all(c['state']=='inferred' for r in refs for c in r['candidates']))

    def test_missing_and_ambiguous_paths_remain_uncertain_without_questions_by_convention(self):
        report=self.discover(**{'service/setup.py':'load("missing.sql")\nload("contract.json")\n','contract.json':'{}','service/contract.json':'{}'})
        self.assertTrue(any(r['resolution']=='unresolved' for r in report['references']))
        self.assertTrue(any(r['resolution']=='ambiguous' for r in report['references']))
        self.assertFalse(any(r.get('requires_user') for r in report['references']))

    def test_shell_and_make_explicit_paths_are_cited_not_executed(self):
        report=self.discover(**{'Makefile':'generate:\n\tpython3 craft/build.py --contract=odd/wire.json\n','craft/build.py':'pass','odd/wire.json':'{}'})
        self.assertTrue(any(r['source']=='Makefile' and r['line']==2 and any(c['path']=='odd/wire.json' and c['exists'] for c in r['candidates']) for r in report['references']))
        self.assertEqual(report['tests'],[])

    def test_assertions_mocks_skips_fixtures_are_expectations_not_runtime_or_provider_proof(self):
        text='''import unittest as u
from unittest.mock import patch as substitute
import pytest as pt
@pt.fixture
def database(): return None
class Cases(u.TestCase):
 @u.skip("private reason never copy")
 @substitute("private.provider.value")
 def test_zero_quantity(self, mock):
  self.assertEqual(create(0), 0)
  with self.assertRaises(ValueError): create(-1)
  assert changed() is False
'''
        report=self.discover(**{'checks/behavior.py':text})
        test=report['tests'][0]
        self.assertEqual(test['name'],'test_zero_quantity')
        self.assertEqual({r['kind'] for r in test['assertions']},{'assertEqual','assertRaises','assert'})
        self.assertEqual(len(test['mocks']),1);self.assertEqual(len(test['skips']),1)
        self.assertFalse(test['runtime_verified'])
        self.assertEqual(report['fixtures'][0]['name'],'database')
        for value in ('private reason','private.provider.value'):
            self.assertNotIn(value,json.dumps(report))

    def test_non_tests_and_deceptive_strings_do_not_become_mock_or_skip_evidence(self):
        report=self.discover(**{'tests/test_fake.py':'def test_example():\n note="@pytest.mark.skip mock.patch"\n assert True\n','app.py':'def invoice():\n assert healthy()\n'})
        self.assertEqual(len(report['tests']),1)
        self.assertEqual(report['tests'][0]['mocks'],[])
        self.assertEqual(report['tests'][0]['skips'],[])

    def test_secret_absolute_dynamic_and_escape_paths_are_not_reported(self):
        report=self.discover(**{'app.py':'a="/private/key.sql"\nb="https://secret.example/api.json"\nc="../../outside.sql"\nd="credentials/wire.json"\ne="${ROOT}/wire.json"\nf=".env.local"\n'})
        self.assertEqual(report['references'],[])
        for marker in ('private/key','secret.example','outside.sql','credentials','${ROOT}'):
            self.assertNotIn(marker,json.dumps(report))

    def test_malformed_python_reports_cited_unknown_without_source_values(self):
        report=self.discover(**{'odd/check.py':'def test_bad(:\n "sensitive"\n'})
        self.assertTrue(any(r['source']=='odd/check.py' and r['line']==1 for r in report['unknowns']))
        self.assertNotIn('sensitive',json.dumps(report))


if __name__=='__main__':unittest.main()
