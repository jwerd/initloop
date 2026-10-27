"""Public discovery evidence stays aligned, bounded, and source-cited."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from initloop.core import Inventory
from initloop.stack import discover
from initloop.workflow import audit, propose


class DiscoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'project'
        self.root.mkdir()
        subprocess.run(['git','init','-q',str(self.root)],check=True)

    def put(self,name,text):
        target=self.root/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_text(text)
        subprocess.run(['git','-C',str(self.root),'add','--',name],check=True)

    def test_sqlite_references_aggregate_lines_but_keep_connection_and_version_evidence(self):
        self.put('consumer.py','import sqlite3\n'+''.join(f'def consumer{i}(db: sqlite3.Connection): pass\n' for i in range(8)))
        self.put('.env.example','ORDERS_DB_CONNECTION=sqlite\nCUSTOMERS_DB_CONNECTION=sqlite\nORDERS_DB_CONNECTION=sqlite\n')
        self.put('compose.yaml','services:\n  old:\n    image: postgres:15\n  new:\n    image: postgres:16\n')
        report=discover(self.root)
        refs=[r for r in report['databases'] if r['source']=='consumer.py' and r['name']=='sqlite']
        self.assertEqual(len(refs),1)
        self.assertEqual(refs[0]['lines'],list(range(1,10)))
        self.assertEqual(refs[0]['line'],1)
        connections=[r for r in report['databases'] if r.get('configuration') and r['name']=='sqlite']
        self.assertEqual({r['configuration'] for r in connections},{'ORDERS_DB_CONNECTION','CUSTOMERS_DB_CONNECTION'})
        orders=next(r for r in connections if r['configuration']=='ORDERS_DB_CONNECTION')
        self.assertEqual(orders['lines'],[1,3])
        self.assertEqual({r['version'] for r in report['databases'] if r['name']=='postgresql'},{'15','16'})

    def test_same_engine_version_named_compose_connections_stay_distinct(self):
        self.put('compose.yaml','services:\n  orders:\n    image: postgres:16\n  customers:\n    image: postgres:16\n')
        rows=[r for r in discover(self.root)['databases'] if r['name']=='postgresql']
        self.assertEqual({r.get('service') for r in rows},{'orders','customers'})
        self.assertEqual(len(rows),2)

    def test_inventory_workflow_stack_align_source_env_and_contracts_without_defaults(self):
        self.put('app/server.py','import os as system\nfrom http.server import ThreadingHTTPServer as Server\nport = system.getenv("PORT", "synthetic-private-default")\nServer(("127.0.0.1", int(port)), Handler)\n')
        self.put('app/db.py','from os import environ as settings\nDB = settings.get("TASKS_DB", "synthetic-private-database")\n')
        self.put('.env.example','EXTRA_OPTION=synthetic-private-template\n')
        self.put('contracts/openapi.yaml','openapi: 3.1.0\npaths:\n  /tasks:\n    get:\n      responses: {}\n    post:\n      responses: {}\n  /tasks/{id}:\n    get:\n      responses: {}\n')
        inventory=Inventory(self.root).scan(); workflow=audit(self.root)
        for result in (inventory,workflow):
            self.assertEqual(set(result['environment_names']),{'PORT','TASKS_DB','EXTRA_OPTION'})
            self.assertEqual({r['name'] for r in result['environment_evidence']},{'PORT','TASKS_DB','EXTRA_OPTION'})
            stack=result['stack']
            self.assertTrue(any(r['source']=='app/server.py' and r['line']==4 for r in stack['app_servers']))
            operations=stack['contracts'][0]['operations']
            self.assertEqual({(r['method'],r['path']) for r in operations},{('GET','/tasks'),('POST','/tasks'),('GET','/tasks/{id}')})
            self.assertTrue(any(r.get('configuration')=='TASKS_DB' for r in result['resources']))
            for marker in ('synthetic-private-default','synthetic-private-database','synthetic-private-template'):
                self.assertNotIn(marker,json.dumps(result))
            self.assertEqual(stack['runner_decision']['status'],'choice_required')
            self.assertTrue(stack['runner_decision']['reason'])
        output=Path(self.tmp.name)/'proposal'
        propose(self.root,output,'reconcile')
        reference=(output/'files/docs/initloop-stack.md').read_text()
        self.assertIn('TASKS_DB',reference)
        self.assertIn('/tasks/{id}',reference)
        self.assertIn('unverified',reference.lower())

    def test_named_source_database_reads_are_not_collapsed_with_engine_lines(self):
        self.put('connections.py','import os, sqlite3\norders = sqlite3.connect(os.getenv("ORDERS_DB", "synthetic-one.db"))\ncustomers = sqlite3.connect(os.getenv("CUSTOMERS_DB", "synthetic-two.db"))\n')
        report=audit(self.root)
        self.assertEqual({row['configuration'] for row in report['resources']},{'ORDERS_DB','CUSTOMERS_DB'})
        refs=[row for row in report['stack']['databases'] if row['source']=='connections.py' and row['name']=='sqlite']
        self.assertEqual(len(refs),1)
        self.assertEqual(refs[0]['lines'],[1,2,3])
        self.assertNotIn('synthetic-one.db',json.dumps(report))
        self.assertNotIn('synthetic-two.db',json.dumps(report))

    def test_contract_examples_do_not_become_configuration_evidence(self):
        self.put('contracts/openapi.json',json.dumps({'openapi':'3.1.0','paths':{'/tasks':{'get':{'responses':{}}}},'components':{'examples':{'demo':{'value':{'DO_NOT_REPORT_URL':'https://private.example/secret','password':'synthetic-private-value'}}}}}))
        report=audit(self.root)
        serialized=json.dumps(report)
        self.assertNotIn('DO_NOT_REPORT_URL',serialized)
        self.assertNotIn('private.example',serialized)
        self.assertNotIn('synthetic-private-value',serialized)
        self.assertEqual(report['stack']['contracts'][0]['operations'][0]['path'],'/tasks')

    def test_python_and_template_values_comments_do_not_become_configuration_names(self):
        self.put('source.py','import os\nport = os.getenv("PORT", "DO_NOT_REPORT_URL")\n# COMMENT_PRIVATE_URL\ndocument = """ANOTHER_PRIVATE_URL"""\nAPI_URL = os.getenv("REAL_API_URL", "https://private.example")\nDB_CONNECTION = "pgsql"\n')
        self.put('.env.example','PORT=TEMPLATE_VALUE_URL\n# TEMPLATE_COMMENT_URL=private\nCUSTOMERS_DATABASE_URL=synthetic-private-value\n')
        self.put('malformed.py','port = os.getenv("PORT", "UNTERMINATED_PRIVATE_URL\n')
        self.put('indentation.py','if True:\n  pass\n pass # INDENT_PRIVATE_URL\n')
        report=audit(self.root)
        serialized=json.dumps(report)
        for marker in ('UNTERMINATED_PRIVATE_URL','INDENT_PRIVATE_URL','DO_NOT_REPORT_URL','COMMENT_PRIVATE_URL','ANOTHER_PRIVATE_URL','TEMPLATE_VALUE_URL','TEMPLATE_COMMENT_URL','private.example','synthetic-private-value'):
            self.assertNotIn(marker,serialized)
        configurations={row.get('configuration') for row in report['stack']['apis']+report['stack']['databases']}
        self.assertTrue({'API_URL','REAL_API_URL','DB_CONNECTION','CUSTOMERS_DATABASE_URL'}.issubset(configurations))
        self.assertTrue(any(row['name']=='postgresql' for row in report['stack']['databases']))
        self.assertEqual(set(report['environment_names']),{'PORT','REAL_API_URL','CUSTOMERS_DATABASE_URL'})

    def test_installed_harness_skill_source_is_not_application_discovery_input(self):
        self.put('.agents/skills/other/app.py','from http.server import HTTPServer\nHTTPServer(address, handler)\nAPI_URL = "synthetic-helper-only"\n')
        self.put('.codex/config.toml','[mcp_servers.example]\ncommand="example"\n')
        result=audit(self.root)
        self.assertFalse(any(r['source'].startswith('.agents/skills/') for r in result['stack']['app_servers']))
        self.assertNotIn('API_URL',result.get('environment_names',[]))
        self.assertNotIn('.agents/skills/other/app.py',result['dependencies'])
        self.assertTrue(any(r['name']=='example' for r in result['tools']))


    def test_repository_evidence_is_additive_and_proposals_cite_unconventional_sources(self):
        self.put('craft/prepare.py','from pathlib import Path\nPath("odd/schema.sql")\n')
        self.put('odd/schema.sql','create table receipts(id integer);\n')
        self.put('checks/test_rules.py','def test_quantity():\n assert total(0) == 0\n')
        report=audit(self.root)
        evidence=report['stack']['repository_evidence']
        self.assertTrue(any(r['source']=='craft/prepare.py' for r in evidence['references']))
        self.assertEqual(evidence['tests'][0]['name'],'test_quantity')
        self.assertFalse(evidence['tests'][0]['runtime_verified'])
        self.assertIn('runner_decision',report['stack'])
        output=Path(self.tmp.name)/'proposal-evidence'
        propose(self.root,output,'reconcile')
        reference=(output/'files/docs/initloop-stack.md').read_text()
        self.assertIn('craft/prepare.py:2',reference)
        self.assertIn('checks/test_rules.py:1',reference)
        self.assertFalse(any(c.get('command')=='total' for c in report['commands']))


    def test_ci_clues_remain_unverified_and_never_become_command_recommendations(self):
        self.put('.github/workflows/check.yml','jobs:\n  verify:\n    defaults:\n      run:\n        working-directory: nested\n    steps:\n      - run: python3 craft.py\n')
        self.put('nested/craft.py','print("synthetic")\n')
        report=audit(self.root)
        evidence=report['stack']['repository_evidence']
        observations=evidence['ci_workflows'][0]['observations']
        self.assertTrue(any(r['kind']=='script' and r['target']=='nested/craft.py' and r['exists'] for r in observations))
        self.assertTrue(all(r['runtime_verified'] is False for r in observations))
        self.assertFalse(any('craft.py' in r['command'] for r in report['commands']))
        self.put('broken.py','def incomplete(:\n')
        self.assertTrue(any(isinstance(r,dict) and r['source']=='broken.py' for r in audit(self.root)['stack']['unknowns']))


    @unittest.skipUnless(os.name=='posix','safe descriptor inventory requires POSIX')
    def test_scan_exclusion_is_visible_in_proposal_provenance(self):
        self.put('Makefile','test:\n\tpython3 -m unittest\n')
        (self.root/'convenience-link').symlink_to('not-installed/runner')
        output=Path(self.tmp.name)/'partial-proposal'
        propose(self.root,output,'reconcile')
        reference=(output/'files/docs/initloop-stack.md').read_text()
        self.assertIn('convenience-link',reference)
        self.assertIn('symlink_dangling',reference)
        self.assertIn('partial',reference)


if __name__=='__main__':unittest.main()
