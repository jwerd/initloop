import json
import tempfile
import unittest
from pathlib import Path
from initloop.stack import discover


class StackDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def put(self, name, content):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def test_manifest_and_lock_versions_have_evidence_and_no_runtime_claim(self):
        self.put('pyproject.toml', '[project]\nrequires-python = ">=3.11"\ndependencies = ["fastapi>=0.110", "uvicorn==0.29.0", "psycopg[binary]>=3"]\n')
        self.put('uv.lock', 'version = 1\n[[package]]\nname = "fastapi"\nversion = "0.115.0"\n')
        self.put('.python-version', '3.12.2\n')
        result = discover(self.root)
        fastapi = [x for x in result['frameworks'] if x['name']=='fastapi']
        self.assertEqual({x['version_kind'] for x in fastapi}, {'declared','resolved'})
        self.assertEqual({x['version'] for x in fastapi}, {'>=0.110','0.115.0'})
        self.assertTrue(all(x['runtime_observed'] is None and x['line']>0 for x in fastapi))
        self.assertTrue(any(x['name']=='uvicorn' for x in result['app_servers']))
        self.assertTrue(any(x['name']=='postgresql' for x in result['databases']))

    def test_existing_compose_preserved_with_topology(self):
        self.put('compose.yaml', '''services:
  api:
    build: .
    depends_on:
      - db
    ports:
      - "127.0.0.1:8090:8000"
    volumes:
      - api-data:/data
  db:
    image: postgres:16.3
volumes:
  api-data:
''')
        result=discover(self.root)
        self.assertEqual(result['runner_decision']['status'],'existing_evidence')
        self.assertIn('compose.yaml',result['runner_decision']['preferred'])
        db=next(x for x in result['databases'] if x['name']=='postgresql')
        self.assertEqual(db['version'],'16.3')
        self.assertTrue(any(x['from']=='api' and x['to']=='db' for x in result['relationships']))
        api=next(x for x in result['services'] if x['name']=='api')
        self.assertEqual(api['ports'],['127.0.0.1:8090:8000'])
        self.assertEqual(api['storage'],['api-data:/data'])
        self.assertIsNone(db['runtime_observed'])

    def test_native_runner_is_preserved_without_docker_requirement(self):
        self.put('package.json',json.dumps({'engines':{'node':'>=20'},'scripts':{'start':'node app.mjs'},'dependencies':{'fastify':'^4.0.0'}}))
        result=discover(self.root)
        self.assertEqual(result['runner_decision']['status'],'existing_evidence')
        self.assertIn('npm run start',[x.get('command') for x in result['runners']])
        self.assertFalse(any(x['kind']=='compose' for x in result['runners']))
        self.assertIn('native',[x['kind'] for x in result['runner_decision']['options']])

    def test_absent_runner_is_choice_not_inaccessible_service(self):
        self.put('requirements.txt','fastapi==0.115.0\nredis>=5\n')
        result=discover(self.root)
        self.assertEqual(result['runner_decision']['status'],'choice_required')
        self.assertEqual({x['kind'] for x in result['runner_decision']['options']},{'native','compose'})
        self.assertNotIn('inaccessible',json.dumps(result).lower())
        self.assertTrue(result['unknowns'])

    def test_unknown_connections_do_not_expose_url_or_assume_access(self):
        self.put('.env.example','CUSTOMERS_DATABASE_URL=postgresql://alice:actual-private-value@private.example:5432/customers\nSHIPPING_URL=https://private.example/private-token\nSHIPPING_TOKEN=another-private-value\n')
        self.put('.env','PRIVATE_TOKEN=unrelated-private-value\n')
        result=discover(self.root)
        serialized=json.dumps(result)
        for secret in ('alice','actual-private-value','another-private-value','unrelated-private-value','private.example','private-token'):
            self.assertNotIn(secret,serialized)
        self.assertTrue(any(x.get('configuration')=='CUSTOMERS_DATABASE_URL' for x in result['databases']))
        self.assertTrue(any(x.get('configuration')=='SHIPPING_URL' for x in result['apis']))

    def test_driver_and_general_api_config_are_evidence_without_values(self):
        self.put('.env.example', 'DB_CONNECTION=pgsql\nFREIGHT_BASE_URL=https://secret-host.test/private-value\n')
        result=discover(self.root)
        self.assertTrue(any(x['name']=='postgresql' and x.get('configuration')=='DB_CONNECTION' for x in result['databases']))
        self.assertTrue(any(x.get('configuration')=='FREIGHT_BASE_URL' for x in result['apis']))
        self.assertNotIn('secret-host',json.dumps(result))

    def test_conflicting_runtime_declarations_are_explicit(self):
        self.put('.python-version','3.12.2\n')
        self.put('Dockerfile','FROM python:3.11-slim\nCMD ["python","main.py"]\n')
        result=discover(self.root)
        self.assertTrue(any(x['name']=='python' for x in result['conflicts']))

    def test_npm_composer_and_go_lock_sources(self):
        self.put('package.json',json.dumps({'dependencies':{'express':'^4.18.0','redis':'^4.0.0'}}))
        self.put('package-lock.json',json.dumps({'lockfileVersion':3,'packages':{'node_modules/express':{'version':'4.21.2'}}}))
        self.put('composer.json',json.dumps({'require':{'php':'^8.2','laravel/framework':'^11.0'}}))
        self.put('composer.lock',json.dumps({'packages':[{'name':'laravel/framework','version':'v11.2.0'}]}))
        self.put('go.mod','module example.test/app\ngo 1.22.0\nrequire github.com/redis/go-redis/v9 v9.5.1\n')
        result=discover(self.root)
        self.assertTrue(any(x['name']=='express' and x['version_kind']=='resolved' for x in result['frameworks']))
        self.assertTrue(any(x['name']=='laravel' and x['version']=='v11.2.0' for x in result['frameworks']))
        self.assertTrue(any(x['name']=='go' and x['version']=='1.22.0' for x in result['runtimes']))
        self.assertTrue(result['caches'])

    def test_runner_paths_are_shell_quoted(self):
        import shlex
        source='packages/service; echo SHOULD_NOT_RUN/compose.yaml'
        result=discover(self.root,{source:b'services:\n  app:\n    image: node:22\n'})
        command=next(x['command'] for x in result['runners'] if x['kind']=='compose')
        self.assertEqual(shlex.split(command),['docker','compose','-f',source,'up'])

    def test_nested_runner_paths_resolve_from_reported_working_directory(self):
        import shlex
        self.put('scripts/dev.sh', '#!/bin/sh\necho ready\n')
        self.put('infra/compose.yaml', 'services:\n  db:\n    image: postgres:16\n')
        report=discover(self.root)
        for runner in report['runners']:
            argv=shlex.split(runner.get('command',''))
            if argv and argv[0]=='sh':candidate=argv[1]
            elif argv[:3]==['docker','compose','-f']:candidate=argv[3]
            else:continue
            self.assertTrue((self.root/runner['scope']/candidate).is_file(),runner)

    def test_supplied_files_do_not_trigger_filesystem_read_or_execution(self):
        files={'README.md':b'Run `python -m app serve` locally.\n', 'Makefile':b'start:\n\tpython -m app serve\n'}
        result=discover(Path('/does/not/exist'),files)
        self.assertTrue(any(x.get('command')=='make start' for x in result['runners']))
        self.assertTrue(any(x['source']=='README.md' for x in result['runners']))


if __name__=='__main__': unittest.main()
