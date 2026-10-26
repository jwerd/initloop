"""Static Python source evidence never imports or executes inspected code."""
import json
from pathlib import Path
import tempfile
import unittest
from initloop.python_source import discover_python


class PythonSourceTests(unittest.TestCase):
    def scan(self, text):
        return discover_python(text, 'app/server.py')

    def test_http_constructor_and_wsgi_aliases_have_exact_lines(self):
        text = ('import http.server as web\n'
                'from wsgiref.simple_server import make_server as create\n'
                'server = web.ThreadingHTTPServer(("127.0.0.1", 8000), Handler)\n'
                'other = create("", 9000, application)\n')
        rows = self.scan(text)['app_servers']
        self.assertEqual([(row['name'], row['line']) for row in rows],
                         [('http.server.ThreadingHTTPServer', 3), ('wsgiref.simple_server.make_server', 4)])
        self.assertTrue(all(row['source'] == 'app/server.py' for row in rows))

    def test_module_import_and_from_import_aliases(self):
        text = ('import http.server\nfrom http import server as h\n'
                'from http.server import HTTPServer as Server\n'
                'http.server.HTTPServer((), Handler)\nh.HTTPServer((), Handler)\nServer((), Handler)\n')
        self.assertEqual([r['line'] for r in self.scan(text)['app_servers']], [4,5,6])

    def test_socket_server_requires_http_handler_proof(self):
        text = ('import socketserver as sockets\n'
                'from http.server import BaseHTTPRequestHandler as Base\n'
                'class Handler(Base):\n    pass\n'
                'sockets.TCPServer(("", 1), Handler)\n'
                'sockets.ThreadingTCPServer(("", 2), RequestHandlerClass=Base)\n'
                'sockets.TCPServer(("", 3), UnknownHandler)\n'
                'sockets.UDPServer(("", 4), Handler)\n')
        rows=self.scan(text)['app_servers']
        self.assertEqual([r['line'] for r in rows],[5,6])
        self.assertTrue(any('HTTP' in r['detail'] for r in self.scan(text)['unknowns']))

    def test_http_subclasses_and_handler_aliases(self):
        text = ('from http.server import HTTPServer, SimpleHTTPRequestHandler\n'
                'from socketserver import ThreadingMixIn, TCPServer\n'
                'class Server(ThreadingMixIn, HTTPServer):\n    pass\n'
                'class SocketServer(TCPServer):\n    pass\n'
                'Handler = SimpleHTTPRequestHandler\n'
                'Server((), Handler)\nSocketServer((), Handler)\n')
        self.assertEqual([r['line'] for r in self.scan(text)['app_servers']],[8,9])

    def test_imports_comments_and_generic_socket_servers_are_not_http(self):
        text = ('# HTTPServer((), Handler)\nimport http.server\nimport socketserver\n'
                'text = "http.server.HTTPServer()"\n'
                'socketserver.TCPServer((), socketserver.BaseRequestHandler)\n')
        self.assertEqual(self.scan(text)['app_servers'],[])

    def test_literal_env_names_and_locations_omit_defaults(self):
        text = ('import os as runtime\nfrom os import environ as env, getenv as read\n'
                'port=runtime.environ["PORT"]\n'
                'db=runtime.environ.get("TASKS_DB", "synthetic-private-default")\n'
                'token=runtime.getenv("API_TOKEN", "synthetic-private-token")\n'
                'env.get("CACHE_HOST")\nread(key="ANOTHER_NAME")\n')
        rows=self.scan(text)['environment']
        self.assertEqual([(r['name'],r['line']) for r in rows], [('PORT',3),('TASKS_DB',4),('API_TOKEN',5),('CACHE_HOST',6),('ANOTHER_NAME',7)])
        serialized=json.dumps(self.scan(text))
        self.assertNotIn('synthetic-private',serialized)
        self.assertNotIn('value',serialized)

    def test_dynamic_environment_keys_are_unknown_not_guessed(self):
        report=self.scan('import os\nos.getenv(variable)\nos.environ[prefix+"_KEY"]\nos.environ.get(f"{prefix}_DB")\n')
        self.assertEqual(report['environment'],[])
        self.assertEqual([r['line'] for r in report['unknowns']],[2,3,4])
        self.assertNotIn('prefix',json.dumps(report))

    def test_env_writes_are_not_reads_and_alias_assignment_is_supported(self):
        text = ('import os\nos.environ["WRITE_ONLY"] = "hidden-value"\n'
                'get = os.getenv\nget("READ_NAME")\n')
        self.assertEqual([r['name'] for r in self.scan(text)['environment']],['READ_NAME'])

    def test_rebinding_shadow_parameters_and_local_bindings_do_not_false_positive(self):
        text = ('import os\nfrom http.server import HTTPServer\n'
                'def f(os, HTTPServer):\n    os.getenv("FAKE")\n    HTTPServer()\n'
                'def g():\n    os.getenv("UNBOUND")\n    os = object()\n'
                'os = object()\nos.getenv("FAKE_TWO")\nHTTPServer = object()\nHTTPServer()\n')
        result=self.scan(text)
        self.assertEqual(result['environment'],[])
        self.assertEqual(result['app_servers'],[])

    def test_import_inside_function_and_outer_defaults(self):
        text = ('import os\ndef f(value=os.getenv("DEFAULT_NAME")):\n'
                '    import os as local\n    return local.environ.get("INNER_NAME")\n')
        self.assertEqual([(r['name'],r['line']) for r in self.scan(text)['environment']], [('DEFAULT_NAME',2),('INNER_NAME',4)])

    def test_class_namespace_does_not_act_as_method_closure(self):
        text = ('class C:\n    import os\n    def method(self):\n        return os.getenv("NOT_GLOBAL")\n')
        self.assertEqual(self.scan(text)['environment'],[])

    def test_nested_class_and_class_lambda_do_not_capture_class_aliases(self):
        for text in ('class Outer:\n    import os\n    class Inner:\n        value=os.getenv("NOT_GLOBAL")\n',
                     'class Outer:\n    import os\n    value=lambda: os.getenv("NOT_GLOBAL")\n'):
            self.assertEqual(self.scan(text)['environment'], [])

    def test_attribute_monkeypatch_and_branch_uncertainty_are_conservative(self):
        text = ('import os\nos.getenv = fake\nos.getenv("FAKE")\n'
                'import os as env\nif flag:\n    env = fake\n'
                'env.getenv("MAYBE_FAKE")\n')
        self.assertEqual(self.scan(text)['environment'],[])

    def test_comprehension_shadow_does_not_escape_or_false_positive(self):
        text = ('import os\n[os.getenv("SHADOWED") for os in things]\n'
                'os.getenv("REAL")\n')
        self.assertEqual([r['name'] for r in self.scan(text)['environment']],['REAL'])

    def test_star_import_and_exception_alias_invalidate_unproven_names(self):
        for text in ('import os\nfrom unknown import *\nos.getenv("UNPROVEN")\n',
                     'import os\ntry:\n    action()\nexcept Exception as os:\n    os.getenv("SHADOWED")\n'):
            self.assertEqual(self.scan(text)['environment'], [])

    def test_conditional_import_does_not_establish_binding_after_try(self):
        text = 'os = unknown\ntry:\n    import os\nexcept ImportError:\n    pass\nos.getenv("UNPROVEN")\n'
        self.assertEqual(self.scan(text)['environment'], [])

    def test_decorated_handler_class_is_not_proven_http(self):
        text = ('import socketserver\nfrom http.server import BaseHTTPRequestHandler\n'
                '@replace\nclass Handler(BaseHTTPRequestHandler):\n    pass\n'
                'socketserver.TCPServer((), Handler)\n')
        self.assertEqual(self.scan(text)['app_servers'], [])

    def test_ast_node_and_depth_budgets_are_enforced(self):
        for text in ('\n'.join('value_%d = 1' % index for index in range(6000)),
                     'value = ' + '+'.join('1' for _ in range(150))):
            report = self.scan(text)
            self.assertEqual(report['environment'], [])
            self.assertEqual(report['app_servers'], [])
            self.assertIn('AST', report['unknowns'][0]['detail'])

    def test_destructuring_delete_augmented_and_annotated_rebindings(self):
        cases = [
            'import os\nos, other = values\nos.getenv("FALSE")',
            'import os\n*other, os = values\nos.getenv("FALSE")',
            'import os\ndel os\nos.getenv("FALSE")',
            'import os\nos += other\nos.getenv("FALSE")',
            'import os\nos: object = replacement\nos.getenv("FALSE")',
            'import os\ndef f():\n    import os\n    def os(): pass\n    os.getenv("FALSE")',
            'import os\ndef f():\n    os.getenv("UNBOUND")\n    try: pass\n    except Exception as os: pass',
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.scan(text)['environment'], [])
        text = 'import os\nvalue: int = os.getenv("ANNOTATED")\nif (reader := os.getenv):\n    reader("WALRUS")\n'
        self.assertEqual([r['name'] for r in self.scan(text)['environment']], ['ANNOTATED','WALRUS'])

    def test_lambda_arguments_defaults_and_global_nonlocal_bindings(self):
        text = ('import os\n'
                'f = lambda os=os.getenv("DEFAULT"): os.getenv("SHADOWED")\n'
                'g = lambda *os: os.getenv("VARARG")\n'
                'h = lambda **os: os.getenv("KWARG")\n'
                'def outer():\n    global os\n    os.getenv("GLOBAL")\n'
                '    def inner():\n        nonlocal value\n        return value\n'
                '    value = 1\n')
        self.assertEqual([r['name'] for r in self.scan(text)['environment']], ['DEFAULT','GLOBAL'])

    def test_loop_and_context_binding_uncertainty(self):
        text = ('import os\nwhile os.getenv("LOOP_TEST"):\n    os.getenv("LOOP_BODY")\n    os = replacement\n'
                'os.getenv("AFTER_UNPROVEN")\nimport os\n'
                'for os in things:\n    os.getenv("FOR_SHADOWED")\n'
                'os.getenv("AFTER_FOR")\nimport os\n'
                'with context() as os:\n    os.getenv("WITH_SHADOWED")\n')
        self.assertEqual([r['name'] for r in self.scan(text)['environment']], ['LOOP_TEST','LOOP_BODY'])

    def test_comprehension_forms_do_not_pollute_outer_aliases(self):
        text = ('import os\n'
                'a={os.getenv("SET") for item in values}\n'
                'b={item: os.getenv("DICT") for item in values if os.getenv("FILTER")}\n'
                'c=(os.getenv("GENERATOR") for item in values)\n'
                'os.getenv("AFTER")\n')
        self.assertEqual({r['name'] for r in self.scan(text)['environment']}, {'SET','DICT','FILTER','GENERATOR','AFTER'})

    def test_try_success_and_finally_imports_and_relative_aliases(self):
        text = ('import os\ntry:\n    os.getenv("TRY")\nexcept ValueError:\n    os.getenv("HANDLER")\n'
                'else:\n    os.getenv("ELSE")\nfinally:\n    os.getenv("FINALLY")\n'
                'from . import os\nos.getenv("RELATIVE_UNPROVEN")\n')
        self.assertEqual({r['name'] for r in self.scan(text)['environment']}, {'TRY','HANDLER','ELSE','FINALLY'})

    def test_comprehension_named_assignment_is_an_uncertain_outer_binding(self):
        for text in ('import os\n[(os := fake) for item in values]\nos.getenv("UNPROVEN")\n',
                     'import os\ndef f():\n    os.getenv("UNBOUND")\n    [(os := fake) for item in values]\n'):
            self.assertEqual(self.scan(text)['environment'], [])

    def test_pattern_capture_and_nontext_inputs_are_explicit_unknowns(self):
        text = 'import os\nmatch value:\n    case os:\n        os.getenv("UNPROVEN")\n'
        report = self.scan(text)
        self.assertEqual(report['environment'], [])
        self.assertTrue(report['unknowns'])
        for text in (None, b'import os', '\ud800'):
            self.assertTrue(self.scan(text)['unknowns'])

    def test_invalid_oversized_and_deep_sources_return_bounded_unknowns(self):
        for text in ('def invalid(', 'x='+'1'*(1024*1024), 'x='+ '['*300+'1'+']'*300):
            result=self.scan(text)
            self.assertEqual(result['app_servers'],[])
            self.assertEqual(result['environment'],[])
            self.assertTrue(result['unknowns'])
            self.assertLess(len(json.dumps(result)),1000)

    def test_inspection_does_not_execute_source_or_disclose_exception_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker=Path(temporary)/'MUST_NOT_EXIST'
            text='from pathlib import Path\nPath('+repr(str(marker))+').write_text("no")\nimport os\nos.getenv("PORT", "private-default")\n'
            report=self.scan(text)
            self.assertFalse(marker.exists())
            self.assertNotIn(temporary,json.dumps(report))
            self.assertNotIn('private-default',json.dumps(report))

    def test_missing_or_unsafe_literal_env_names_do_not_leak(self):
        report=self.scan('import os\nos.getenv()\nos.getenv("PRIVATE-VALUE-WITH-PUNCTUATION")\nos.getenv("x"*200)\n')
        self.assertEqual(report['environment'],[])
        self.assertEqual(len(report['unknowns']),3)


if __name__=='__main__':
    unittest.main()
