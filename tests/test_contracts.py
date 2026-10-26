"""Contract discovery is static, bounded and deliberately not a full YAML parser."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from initloop.contracts import discover_contract


class ContractDiscoveryTests(unittest.TestCase):
    def test_json_operations_have_exact_source_lines_without_payloads(self):
        text = '''{
  "openapi": "3.0.3",
  "info": {"title": "private-title", "version": "private-version"},
  "paths": {
    "/tasks": {
      "get": {"responses": {}},
      "post": {"requestBody": {"example": {"password": "private-example"}}}
    },
    "/tasks/{id}": {
      "get": {"responses": {}}
    }
  }
}'''
        report = discover_contract(text, 'contracts/openapi.json')
        self.assertEqual((report['name'], report['version'], report['line']), ('openapi', '3.0.3', 2))
        self.assertEqual([(r['method'], r['path'], r['line']) for r in report['operations']],
                         [('GET', '/tasks', 6), ('POST', '/tasks', 7), ('GET', '/tasks/{id}', 10)])
        self.assertTrue(all(r['source'] == 'contracts/openapi.json' for r in report['operations']))
        self.assertNotIn('private-', json.dumps(report))

    def test_conventional_yaml_operations_and_swagger(self):
        text = '''# A static contract
openapi: 3.1.0
info:
  title: anything
paths:
  /tasks:
    get:
      responses:
        '200':
          description: tasks
    post: {}
  '/tasks/{id}':
    get:
      responses: {}
'''
        report = discover_contract(text, 'contracts/openapi.yaml')
        self.assertEqual(report['version'], '3.1.0')
        self.assertEqual([(r['method'], r['path'], r['line']) for r in report['operations']],
                         [('GET', '/tasks', 7), ('POST', '/tasks', 11), ('GET', '/tasks/{id}', 13)])
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(report['limitations'])
        other = discover_contract(text.replace('openapi: 3.1.0', 'swagger: "2.0"'), 'schema.yml')
        self.assertEqual((other['name'], other['version']), ('swagger', '2.0'))

    def test_all_supported_methods_and_metadata_are_not_operations(self):
        methods = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']
        value = {'openapi': '3.0.0', 'paths': {'/tasks': {m: {} for m in methods}}}
        value['paths']['/tasks'].update(parameters=[], summary='get', description='post')
        report = discover_contract(json.dumps(value), 'api.json')
        self.assertEqual({r['method'] for r in report['operations']}, {m.upper() for m in methods})

    def test_unrelated_and_invalid_contracts(self):
        self.assertIsNone(discover_contract('{"name":"package"}', 'package.json'))
        for text in ('{', 'openapi: [3.0]\npaths:\n', '{"openapi":"3.0.0","paths":[]}'):
            with self.subTest(text=text):
                report = discover_contract(text, 'openapi.yaml' if not text.startswith('{') else 'openapi.json')
                self.assertIn(report['status'], ('unsupported', 'partial'))
                self.assertEqual(report['operations'], [])
                self.assertTrue(report['limitations'])

    def test_duplicate_keys_and_yaml_features_do_not_fabricate_operations(self):
        documents = [
            ('openapi.json', '{"openapi":"3.0.0","paths":{"/tasks":{"get":{},"get":{}}}}'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths:\n  /tasks:\n    get: {}\n    get: {}\n'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths: {"/tasks": {get: {}}}\n'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths: &routes\n  /tasks:\n    get: {}\n'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths: *routes\n'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths: !!python/object/apply:os.system [touch sentinel]\n'),
            ('openapi.yaml', 'openapi: 3.0.0\npaths: {}\n---\nopenapi: 3.1.0\n'),
        ]
        for source, text in documents:
            with self.subTest(source=source, text=text):
                report = discover_contract(text, source)
                self.assertEqual(report['status'], 'unsupported')
                self.assertEqual(report['operations'], [])

    def test_refs_are_never_fetched_or_expanded(self):
        report = discover_contract(json.dumps({'openapi': '3.0.3', 'paths': {
            '/tasks': {'$ref': 'https://private-host.test/private-path'},
            '/ready': {'get': {'responses': {'200': {'$ref': '#/components/private'}}}}
        }}), 'openapi.json')
        self.assertEqual([(r['method'], r['path']) for r in report['operations']], [('GET', '/ready')])
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(any('reference' in x.lower() for x in report['limitations']))
        self.assertNotIn('private', json.dumps(report))
        yaml = discover_contract('openapi: 3.0.0\npaths:\n  /tasks:\n    $ref: https://private-host.test/x\n', 'openapi.yaml')
        self.assertEqual(yaml['operations'], [])
        self.assertNotIn('private-host', json.dumps(yaml))

    def test_literal_blocks_comments_and_strings_do_not_become_routes(self):
        text = '''openapi: 3.0.0
info:
  description: |
    paths:
      /not-a-route:
        get: {}
# paths: {"/also-false": {post: {}}}
paths:
  /real:
    get:
      description: "A !tag or &anchor is just quoted prose"
      responses: {}
'''
        report = discover_contract(text, 'openapi.yaml')
        self.assertEqual([(r['method'], r['path'], r['line']) for r in report['operations']], [('GET', '/real', 10)])

    def test_unrelated_features_remain_unrelated_and_cr_citations_are_correct(self):
        self.assertIsNone(discover_contract('{"name":"x","name":"y"}', 'package.json'))
        self.assertIsNone(discover_contract('services:\n  app: &app\n    image: python\n', 'compose.yaml'))
        report = discover_contract('{\r"openapi":"3.0.0",\r"paths":{\r"/tasks":{\r"get":{}\r}\r}\r}', 'openapi.json')
        self.assertEqual(report['operations'][0]['line'], 5)
        yaml = discover_contract('openapi: 3.0.0\npaths:\n  /tasks: # comment\n    get: # comment\n      responses: {}\n', 'openapi.yaml')
        self.assertEqual([(r['method'], r['path']) for r in yaml['operations']], [('GET', '/tasks')])

    def test_malformed_and_partial_shapes_remain_bounded_without_leaking_values(self):
        cases = [
            ('[]', 'openapi.json', 'unsupported'),
            ('{"openapi":"3.0.0","swagger":"2.0"}', 'api.json', 'unsupported'),
            ('{"openapi":"3.0.0","paths":{"/tasks":[],"/ready":{"get":"private-body"}}}', 'api.json', 'partial'),
            ('{"openapi":"3.0.0","paths":{"/tasks":{"get":{},"parameters":[{},1,"private-value"]}}}', 'api.json', 'static'),
            ('openapi: 3.0.0\n', 'openapi.yaml', 'partial'),
            ('openapi: 3.0.0\npaths:\n\t/tasks:\n    get: {}\n', 'openapi.yaml', 'unsupported'),
            ('openapi: 3.0.0\npaths:\n  /tasks:\n   get: {}\n', 'openapi.yaml', 'partial'),
            ('openapi: 3.0.0\npaths:\n  /tasks:\n    get: private-body\n', 'openapi.yaml', 'partial'),
            ('openapi: 3.0.0\npaths:\n  /tasks:\n    get: {}\n  /tasks:\n    post: {}\n', 'openapi.yaml', 'unsupported'),
            ('openapi: 3.0.0\nopenapi: 3.1.0\n', 'openapi.yaml', 'unsupported'),
            ('openapi: 3.0.0\nswagger: 2.0\n', 'openapi.yaml', 'unsupported'),
            ('openapi: 3.0.0\npaths:\n  /tasks:\n    get [private-value]\n', 'openapi.yaml', 'partial'),
        ]
        for text, source, status in cases:
            with self.subTest(source=source, text=text):
                report = discover_contract(text, source)
                self.assertEqual(report['status'], status)
                self.assertNotIn('private-', json.dumps(report))
        self.assertIsNone(discover_contract('{', 'api.json'))
        self.assertIsNone(discover_contract(None, 'api.json'))
        self.assertEqual(discover_contract(None, 'openapi.json')['status'], 'unsupported')
        self.assertEqual(discover_contract('openapi: 3.0.0\x00', 'openapi.yaml')['status'], 'unsupported')
        self.assertIsNone(discover_contract('\x00', 'data.yaml'))
        large = json.dumps({'openapi':'3.0.0','paths':{},'metadata':[0]*20001})
        self.assertEqual(discover_contract(large, 'api.json')['status'], 'unsupported')
        self.assertIsNone(discover_contract('x'*(1024*1024+1), 'data.yaml'))

    def test_quoted_yaml_keys_escapes_and_document_end(self):
        text = '\n'.join(['---', '"openapi": "3.0.0" # version', 'info:',
                          '  title: "quoted \\"get: no\\""', '  description: \'Don\'\'t copy this\'',
                          'paths:', '  "/tasks":', '    "get": {}', '...'])
        report = discover_contract(text, 'schema.yaml')
        self.assertEqual([(r['method'], r['path'], r['line']) for r in report['operations']], [('GET', '/tasks', 8)])
        bad = discover_contract('openapi: 3.0.0\n...\npaths:\n  /tasks:\n    get: {}\n', 'openapi.yaml')
        self.assertEqual(bad['status'], 'unsupported')
        self.assertEqual(bad['operations'], [])

    def test_unsafe_path_and_version_values_are_omitted(self):
        marker = 'sk-' + 'syntheticprivate012345678901'
        report = discover_contract(json.dumps({'openapi': 'private-version', 'paths': {'/'+marker: {'get': {}}}}), 'openapi.json')
        self.assertIsNone(report['version'])
        self.assertNotIn(marker, json.dumps(report))
        self.assertNotIn('private-version', json.dumps(report))
        valid = discover_contract(json.dumps({'openapi': '3.0.0', 'paths': {'/'+marker: {'get': {}}, '/tasks': {'get': {}}}}), 'openapi.json')
        self.assertEqual([r['path'] for r in valid['operations']], ['/tasks'])
        self.assertNotIn(marker, json.dumps(valid))

    def test_unsupported_route_syntax_cannot_reuse_previous_route(self):
        prefixes = ('  /second', '  ? /second', '   /second:', ' /second:', '  "unterminated:', '    /second', '    ? /second', '    /second:', '     /second:')
        for unsupported in prefixes:
            with self.subTest(unsupported=unsupported):
                text = ('openapi: 3.0.0\npaths:\n  /first:\n    get: {}\n' +
                        unsupported + '\n    post: {}\n  /third:\n    delete: {}\n')
                report = discover_contract(text, 'openapi.yaml')
                self.assertEqual(report['status'], 'partial')
                self.assertEqual([(r['method'], r['path'], r['line']) for r in report['operations']],
                                 [('GET', '/first', 4), ('DELETE', '/third', 8)])
                self.assertTrue(any('unsupported' in limitation.lower() for limitation in report['limitations']))

    def test_reference_and_tag_inputs_never_execute_or_access_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / 'must-not-exist'
            tagged = 'openapi: 3.0.0\npaths: !!python/object/apply:os.system ["touch ' + str(sentinel) + '"]\n'
            referred = json.dumps({'openapi':'3.0.0','paths':{'/tasks':{'$ref':'https://127.0.0.1:1/private'}}})
            with patch('urllib.request.urlopen', side_effect=AssertionError('network fetch forbidden')), patch('subprocess.run', side_effect=AssertionError('execution forbidden')):
                self.assertEqual(discover_contract(tagged, 'openapi.yaml')['status'], 'unsupported')
                self.assertEqual(discover_contract(referred, 'openapi.json')['status'], 'partial')
            self.assertFalse(sentinel.exists())

    def test_budgets_invalid_depth_and_path_shapes(self):
        for text in ('x' * (1024*1024+1), '{"openapi":"3.0.0","x":' + '['*1000 + '0' + ']'*1000 + '}'):
            report = discover_contract(text, 'openapi.json')
            self.assertEqual(report['status'], 'unsupported')
            self.assertEqual(report['operations'], [])
        for path in ('https://private.test/tasks', '/tasks?token=private', '/tasks/{unclosed', '/tasks/\nprivate'):
            report = discover_contract(json.dumps({'openapi':'3.0.0','paths':{path:{'get':{}}}}), 'api.json')
            self.assertEqual(report['operations'], [])
            self.assertNotIn('private', json.dumps(report))


if __name__ == '__main__':
    unittest.main()
