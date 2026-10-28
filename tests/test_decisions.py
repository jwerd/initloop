"""Shared dependency decisions never execute application setup."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from initloop.decisions import Checkpoint


def catalog():
    return [{'id': name, 'label': name.title(), 'evidence': ['synthetic fixture'],
             'options': [{'id': 'local', 'label': 'Local substitute', 'evidence': ['fixture contract'],
                          'impact': 'Isolated configuration; no source edits',
                          'access': 'Local runner approval', 'unsupported': 'Corporate behavior',
                          'verification': 'Exercise consumer paths'},
                         {'id': 'corporate', 'label': 'Corporate service', 'evidence': ['fixture contract'],
                          'impact': 'External connection', 'access': 'Approved development access',
                          'unsupported': 'Unavailable without access', 'verification': 'Real provider tests'}],
             'suggested': 'local'} for name in ['ldap', 'email', 'reporting']]


class DecisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.project = Path(self.tmp.name) / 'app'
        self.project.mkdir()
        (self.project / 'auth.py').write_text('# preserve authentication\n')
        self.path = Path(self.tmp.name) / 'decisions'
        self.cp = Checkpoint.create(self.project, self.path, catalog())

    def test_suggestions_are_not_selections_and_review_requires_all(self):
        self.assertTrue(all(d['status'] == 'suggested' and d['selected'] is None
                            for d in self.cp.state['dependencies']))
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.cp.review()

    def test_multiple_investigations_return_resume_and_revisit(self):
        self.cp.investigate(['ldap', 'email'])
        self.cp.findings('ldap', 'No approved dev directory; I need something local')
        self.cp.select('ldap', 'local')
        self.cp.back()
        resumed = Checkpoint(self.path)
        self.assertEqual(resumed.state['phase'], 'overview')
        ldap, email, reporting = resumed.state['dependencies']
        self.assertEqual(ldap['selected'], 'local')
        self.assertIn('No approved', ldap['findings'][0])
        self.assertEqual(email['status'], 'suggested')
        self.assertIsNone(reporting['selected'])
        resumed.investigate(['email', 'reporting'])
        resumed.back()
        resumed.investigate(['ldap'])
        self.assertEqual(resumed.state['dependencies'][0]['selected'], 'local')

    def test_conflict_retains_choice_but_blocks_review_until_explicit_reselection(self):
        for name in ['ldap', 'email', 'reporting']:
            self.cp.select(name, 'local')
        self.cp.findings('email', 'New transport evidence invalidates reporting choice', affected=['reporting'])
        row = self.cp.state['dependencies'][2]
        self.assertEqual(row['status'], 'blocked')
        self.assertEqual(row['selected'], 'local')
        with self.assertRaisesRegex(ValueError, 'unresolved'):
            self.cp.review()
        self.cp.select('reporting', 'corporate')
        self.assertEqual(self.cp.review()['phase'], 'review')

    def test_review_back_cancel_and_resume_have_no_application_side_effects(self):
        before = (self.project / 'auth.py').read_bytes()
        for name in ['ldap', 'email', 'reporting']:
            self.cp.select(name, 'local')
        self.cp.review()
        self.cp.back()
        self.cp.select('email', 'corporate')
        self.cp.review()
        self.cp.cancel()
        resumed = Checkpoint(self.path)
        self.assertEqual(resumed.state['phase'], 'cancelled')
        with self.assertRaisesRegex(ValueError, 'resume'):
            resumed.select('ldap', 'corporate')
        resumed.resume()
        self.assertEqual(resumed.state['dependencies'][1]['selected'], 'corporate')
        self.assertEqual((self.project / 'auth.py').read_bytes(), before)
        self.assertEqual(list(self.project.iterdir()), [self.project / 'auth.py'])
        self.assertFalse(resumed.state['applied'])

    def test_unknown_dev_login_cannot_be_selected_and_invalid_batches_are_atomic(self):
        original = copy.deepcopy(self.cp.state)
        with self.assertRaises(ValueError):
            self.cp.select('ldap', 'dev-login')
        with self.assertRaises(ValueError):
            self.cp.investigate(['ldap', 'missing'])
        with self.assertRaises(ValueError):
            self.cp.findings('ldap', 'finding', affected=['missing'])
        self.assertEqual(self.cp.state, original)
        self.assertEqual(json.loads((self.path / 'decisions.json').read_text()), original)

    def test_guards_and_evidence_required(self):
        for path in [self.project / 'state', self.project.parent]:
            with self.assertRaises(ValueError):
                Checkpoint.create(self.project, path, catalog())
        with self.assertRaises(ValueError):
            Checkpoint.create(self.project, self.path, catalog())
        bad = catalog()
        bad[0]['options'][0]['evidence'] = []
        with self.assertRaises(ValueError):
            Checkpoint.create(self.project, self.path.parent / 'bad', bad)
        self.assertFalse((self.path.parent / 'bad').exists())

    def test_source_drift_invalidates_review_without_overwriting_selections(self):
        for name in ['ldap', 'email', 'reporting']:
            self.cp.select(name, 'local')
        (self.project / 'auth.py').write_text('# changed configuration contract\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.cp.review()
        self.assertTrue(all(d['selected'] == 'local' and d['status'] == 'blocked'
                            for d in Checkpoint(self.path).state['dependencies']))

    def test_blocked_option_stale_writer_and_invalid_state(self):
        rows = catalog()
        rows[0]['options'][1]['blocked'] = 'No approved directory'
        cp = Checkpoint.create(self.project, self.path.parent / 'other', rows)
        with self.assertRaisesRegex(ValueError, 'No approved'):
            cp.select('ldap', 'corporate')
        stale = Checkpoint(self.path)
        self.cp.select('ldap', 'local')
        with self.assertRaisesRegex(ValueError, 'reload'):
            stale.select('email', 'local')
        (self.path / 'decisions.json').write_text('{"schema":99}')
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            Checkpoint(self.path)

    def test_interactive_batch_review_back_cancel_resume(self):
        from initloop.decisions import interactive
        answers = iter(['nonsense', '1,2', '1', 'back', '3', '0',
                        '2,3', '1', '1', 'review', 'back', 'cancel', '1', 'resume', 'quit'])
        output = []
        interactive(self.cp, read=lambda _: next(answers), write=output.append)
        self.assertEqual(self.cp.state['phase'], 'overview')
        self.assertTrue(all(r['selected'] == 'local' for r in self.cp.state['dependencies']))
        self.assertIn('Combined plan', '\n'.join(output))
        self.assertIn('resume the cancelled', '\n'.join(output))

    def test_interactive_eof_retains_state_and_callback_records_findings(self):
        from initloop.decisions import interactive
        answers = iter(['1', '1'])
        def read(_):
            try:
                return next(answers)
            except StopIteration:
                raise EOFError()
        interactive(self.cp, read=read, write=lambda _: None,
                    investigate=lambda cp, name, read, write: cp.findings(name, 'Synthetic finding'))
        self.assertEqual(Checkpoint(self.path).state['dependencies'][0]['findings'], ['Synthetic finding'])

    def test_catalog_revision_preserves_choices_and_blocks_changed_capabilities(self):
        self.cp.select('ldap', 'local')
        self.cp.select('email', 'local')
        self.cp.findings('ldap', 'New supported configuration discovered')
        revised = catalog()
        revised[0]['options'][0]['impact'] = 'Changed isolated configuration'
        revised[0]['options'].append(dict(revised[0]['options'][0], id='new-local'))
        self.cp.revise(revised)
        ldap, email, _ = Checkpoint(self.path).state['dependencies']
        self.assertEqual(ldap['selected'], 'local')
        self.assertEqual(ldap['status'], 'blocked')
        self.assertEqual(email['status'], 'selected')
        self.assertIn('New supported', ldap['findings'][0])
        self.cp.select('ldap', 'new-local')
        self.assertEqual(self.cp.state['dependencies'][0]['status'], 'selected')

    def test_demo_directory_back_returns_without_option_prompt(self):
        import importlib.util
        from initloop.decisions import interactive
        spec = importlib.util.spec_from_file_location('demo', Path(__file__).resolve().parents[1] / 'skills/initloop/scripts/demo_checkpoint.py')
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        prompts = []
        answers = iter(['1', 'back', 'quit'])
        def read(prompt):
            prompts.append(prompt)
            return next(answers)
        interactive(self.cp, read=read, write=lambda _: None, investigate=demo.investigate)
        self.assertNotIn('ldap> ', prompts)

    def test_cli_persistence_and_errors(self):
        from contextlib import redirect_stdout, redirect_stderr
        import io
        from initloop.cli import main
        directory = self.path.parent / 'cli'
        catalog_path = self.path.parent / 'catalog.json'
        catalog_path.write_text(json.dumps(catalog()))
        def run(*args):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                return main(['checkpoint', str(directory)] + list(args))
        self.assertEqual(run('--action', 'create'), 2)
        self.assertEqual(run('--action', 'create', '--project', str(self.project), '--catalog', str(catalog_path)), 0)
        self.assertEqual(run(), 0)
        self.assertEqual(run('--action', 'investigate', '--dependency', 'ldap', '--dependency', 'email'), 0)
        self.assertEqual(run('--action', 'select'), 2)
        self.assertEqual(run('--action', 'findings', '--dependency', 'ldap', '--finding', 'No approved directory'), 0)
        for name in ['ldap', 'email', 'reporting']:
            self.assertEqual(run('--action', 'select', '--dependency', name, '--option', 'local'), 0)
        self.assertEqual(run('--action', 'review'), 0)
        self.assertEqual(run('--action', 'back'), 0)
        self.assertEqual(run('--action', 'cancel'), 0)
        self.assertEqual(run('--action', 'resume'), 0)
        self.assertEqual(run('--action', 'revise'), 2)
        self.assertEqual(run('--action', 'revise', '--catalog', str(catalog_path)), 0)
        self.assertFalse(Checkpoint(directory).state['applied'])
