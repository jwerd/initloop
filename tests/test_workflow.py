import json
import tempfile
import unittest
from pathlib import Path
from initloop.workflow import audit, propose, refresh

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'project'
        self.root.mkdir()
        self.out = Path(self.temp.name) / 'proposal'
    def put(self, path, text):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p
    def test_empty_is_unverified(self):
        report = audit(self.root)
        self.assertEqual(report['readiness'], 'unverified')
        self.assertIn('missing_instructions', [f['code'] for f in report['findings']])
    def test_preserve_changes_nothing(self):
        p = self.put('AGENTS.md', 'Never merge without approval.\n')
        propose(self.root, self.out)
        self.assertEqual(p.read_text(), 'Never merge without approval.\n')
        self.assertFalse((self.out / 'files').exists())
    def test_reconcile_nested_and_command_evidence(self):
        self.put('AGENTS.md', 'Never deploy.\n')
        self.put('api/CLAUDE.md', 'Review API tests.\n')
        self.put('package.json', '{"scripts":{"test":"node test.js"}}')
        result = propose(self.root, self.out, 'reconcile')
        self.assertFalse(result['applied'])
        self.assertTrue((self.out / 'files/AGENTS.md').read_text().startswith('Never deploy.\n'))
        self.assertTrue((self.out / 'files/CLAUDE.md').is_file())
        self.assertIn('../docs/initloop-workflow.md', (self.out / 'files/api/CLAUDE.md').read_text())
        doc = (self.out / 'files/docs/initloop-workflow.md').read_text()
        self.assertIn('npm run test', doc)
        self.assertIn('unverified', doc)
        self.assertNotIn('Sol', doc)
    def test_proposal_has_linked_stack_and_runbook_with_evidenced_commands(self):
        self.put('package.json', '{"engines":{"node":">=20"},"scripts":{"start":"node server.js","test":"node --test","logs":"cat app.log"},"dependencies":{"express":"^4.0.0"}}')
        self.put('AGENTS.md', 'Never deploy.\n')
        result = propose(self.root, self.out, 'reconcile')
        for name in ('initloop-stack.md', 'initloop-runbook.md', 'initloop-workflow.md'):
            self.assertIn('docs/' + name, result['affected_files'])
            self.assertTrue((self.out / 'files/docs' / name).is_file())
        stack = (self.out / 'files/docs/initloop-stack.md').read_text()
        runbook = (self.out / 'files/docs/initloop-runbook.md').read_text()
        entry = (self.out / 'files/AGENTS.md').read_text()
        self.assertIn('node', stack.lower())
        self.assertIn('package.json', stack)
        self.assertIn('npm run start', runbook)
        self.assertIn('npm run test', runbook)
        self.assertIn('npm run logs', runbook)
        self.assertIn('runtime-observed', stack)
        self.assertIn('not sandboxed', runbook)
        self.assertIn('not tested', runbook)
        self.assertIn('initloop-stack.md', entry)
        self.assertIn('initloop-runbook.md', entry)
        self.assertEqual((self.root / 'AGENTS.md').read_text(), 'Never deploy.\n')
        self.assertFalse((self.root / 'docs').exists())

    def test_stack_reference_keeps_version_evidence_and_missing_checks_explicit(self):
        self.put('package.json', '{"engines":{"node":">=20"},"dependencies":{"express":"^4.18.0"},"scripts":{"start":"node app.js"}}')
        self.put('package-lock.json', '{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.3"}}}')
        result = propose(self.root, self.out, 'reconcile')
        doc = (self.out / 'files/docs/initloop-stack.md').read_text()
        self.assertIn('declared', doc)
        self.assertIn('resolved', doc)
        self.assertIn('package-lock.json', doc)
        self.assertIn('4.18.3', doc)
        self.assertIn('unknown', doc)
        self.assertIn('not adopted', doc)
        self.assertIn('Tested revision: not tested', doc)
        self.assertFalse(result['applied'])

    def test_existing_stack_and_runbook_are_not_overwritten(self):
        for name in ('initloop-stack.md', 'initloop-runbook.md'):
            with self.subTest(name=name):
                self.put('docs/' + name, 'Human maintained workflow')
                with self.assertRaisesRegex(ValueError, 'manually'):
                    propose(self.root, self.out / name, 'reconcile')
                self.assertFalse((self.out / name).exists())
                (self.root / 'docs' / name).unlink()

    def test_replace_selection_backup(self):
        self.put('AGENTS.md', 'Original policy\n')
        with self.assertRaises(ValueError):
            propose(self.root, self.out, 'replace')
        propose(self.root, self.out, 'replace', ['AGENTS.md'])
        self.assertEqual((self.out / 'originals/AGENTS.md').read_text(), 'Original policy\n')
        self.assertEqual((self.root / 'AGENTS.md').read_text(), 'Original policy\n')

    def test_replace_selection_does_not_authorize_discarding_team_permissions(self):
        self.put('AGENTS.md','Never merge or deploy without team approval.\n')
        with self.assertRaisesRegex(ValueError,'policy'):
            propose(self.root,self.out,'replace',['AGENTS.md'])
        self.assertFalse(self.out.exists())
    def test_instruction_credentials_are_not_copied_to_proposal(self):
        self.put('AGENTS.md', 'API_TOKEN=actual-private-value\n')
        with self.assertRaisesRegex(ValueError, 'credential'):
            propose(self.root, self.out, 'reconcile')
        self.assertFalse(self.out.exists())

    def test_path_and_destination_guards(self):
        with self.assertRaises(ValueError):
            propose(self.root, self.root / 'out', 'reconcile')
        with self.assertRaises(ValueError):
            propose(self.root, self.out, 'replace', ['../AGENTS.md'])
        self.out.mkdir()
        (self.out / 'valuable').write_text('keep')
        with self.assertRaises(ValueError):
            propose(self.root, self.out)
        self.assertEqual((self.out / 'valuable').read_text(), 'keep')
    def test_secrets_symlinks_tools(self):
        secret = self.put('.env', 'TOKEN=DO_NOT_REPORT')
        self.put('.mcp.json', '{"mcpServers":{"shipping":{"env":{"TOKEN":"DO_NOT_REPORT"}}}}')
        (self.root / 'AGENTS.md').symlink_to(secret)
        report = audit(self.root)
        self.assertNotIn('DO_NOT_REPORT', json.dumps(report))
        self.assertEqual(report['tools'][0]['availability'], 'declared_only')
        self.assertEqual(report['instructions'], [])
    def test_drift_never_recertifies(self):
        self.put('package.json', '{"scripts":{"test":"node test.js"}}')
        self.put('compose.yaml', 'services:\n  db:\n    image: postgres:16\n')
        result = propose(self.root, self.out, 'reconcile')
        manifest = Path(result['manifest_path'])
        frozen = manifest.read_bytes()
        self.assertEqual(refresh(self.root, manifest)['status'], 'unverified')
        self.put('package.json', '{"scripts":{"test":"node other.js"}}')
        self.put('compose.yaml', 'services:\n  cache:\n    image: redis:7\n')
        self.put('requirements.txt', 'requests\n')
        drift = refresh(self.root, manifest)
        self.assertEqual(drift['status'], 'stale')
        self.assertEqual(set(drift['changed']), {'package.json', 'compose.yaml'})
        self.assertIn('requirements.txt', drift['added'])
        self.assertEqual(manifest.read_bytes(), frozen)
    def test_scoped_policy_and_stale_command_review(self):
        self.put('AGENTS.md', 'Never deploy. Run `npm run absent`.\n')
        self.put('web/AGENTS.md', 'Always deploy.\n')
        self.put('package.json', '{"scripts":{"test":"node test.js"}}')
        report = audit(self.root)
        codes = [f['code'] for f in report['findings']]
        self.assertIn('policy_review_required', codes)
        self.assertIn('unknown_script_reference', codes)
        self.assertEqual({i['scope'] for i in report['instructions']}, {'.', 'web'})

    def test_other_commands_and_toml_tools(self):
        self.put('Makefile', 'test:\n\tpython -m unittest\n')
        self.put('pyproject.toml', '[project.scripts]\nserve = "app:main"\n')
        self.put('.codex/config.toml', '[mcp_servers.database]\ncommand = "private command"\n')
        report = audit(self.root)
        self.assertEqual({c['command'] for c in report['commands']}, {'make test', 'serve'})
        self.assertEqual(report['tools'][0]['name'], 'database')
        self.assertNotIn('private command', json.dumps(report))
    def test_existing_shared_docs_preflight_preserves_all_files(self):
        self.put('docs/initloop-workflow.md', 'Human documentation')
        with self.assertRaises(ValueError):
            propose(self.root, self.out, 'reconcile')
        self.assertFalse(self.out.exists())

    def test_missing_dependency_documentation(self):
        self.put('compose.yaml', 'services:\n  db:\n    image: postgres:16\n')
        self.put('.mcp.json', '{"mcpServers":{"search":{}}}')
        codes = {f['code'] for f in audit(self.root)['findings']}
        self.assertIn('missing_service_documentation', codes)
        self.assertIn('missing_tool_documentation', codes)

    def test_invalid_provenance_is_rejected(self):
        manifest=Path(self.temp.name)/'manifest.json'
        for value in [[],{'schema_version':1,'dependencies':[]}]:
            manifest.write_text(json.dumps(value))
            with self.assertRaises(ValueError): refresh(self.root,manifest)

    def test_synthetic_environment_template_changes_invalidate_provenance(self):
        self.put('.env.example','DB_CONNECTION=sqlite\n')
        self.put('.env','PASSWORD=do-not-include\n')
        result=propose(self.root,self.out)
        manifest=Path(result['manifest_path'])
        self.put('.env.example','DB_CONNECTION=postgres\nQUEUE_HOST=queue\n')
        drift=refresh(self.root,manifest)
        self.assertEqual(drift['status'],'stale')
        self.assertEqual(drift['changed'],['.env.example'])
        self.assertNotIn('.env',audit(self.root)['dependencies'])
        self.assertNotIn('do-not-include',json.dumps(audit(self.root)))
        self.assertNotIn('PASSWORD',json.dumps(audit(self.root)))
        self.assertIn('.env.example', audit(self.root)['dependencies'])
