"""Bounded Python AST evidence, without importing or executing inspected source.

Only names/locations and recognized stdlib capabilities are reported. Imported
aliases are tracked lexically; dynamic keys and unproven bindings stay unknown.
This is not a whole-program resolver and does not establish runtime availability.
"""
import ast
import re


_MAX_BYTES = 1024 * 1024
_MAX_NODES = 20000
_MAX_DEPTH = 100
_HTTP_SERVERS = {'http.server.HTTPServer', 'http.server.ThreadingHTTPServer'}
_HTTP_HANDLERS = {'http.server.BaseHTTPRequestHandler',
                  'http.server.SimpleHTTPRequestHandler', 'http.server.CGIHTTPRequestHandler'}
_SOCKET_SERVERS = {'socketserver.TCPServer', 'socketserver.ThreadingTCPServer',
                   'socketserver.ForkingTCPServer'}
_WSGI = 'wsgiref.simple_server.make_server'
_HANDLER = '@http-handler'


def _targets(node):
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return set().union(*(_targets(item) for item in node.elts)) if node.elts else set()
    if isinstance(node, ast.Starred):
        return _targets(node.value)
    return set()


class _Bindings(ast.NodeVisitor):
    """Local bindings shadow enclosing names throughout a function's body."""
    def __init__(self):
        self.names = set()
        self.globals = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node):
        self.names.update(alias.asname or alias.name.split('.')[0] for alias in node.names)

    def visit_ImportFrom(self, node):
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_ExceptHandler(self, node):
        if node.name:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.names.add(node.name)

    def visit_Global(self, node):
        self.globals.update(node.names)

    def visit_Nonlocal(self, node):
        # Nonlocal assignment cannot be resolved safely without control flow.
        self.names.update(node.names)

    def visit_ListComp(self, node):
        # Assignment expressions bind outside comprehension iteration scope.
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.names.update(_targets(child.target))

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp


class _Evidence(ast.NodeVisitor):
    def __init__(self, source):
        self.source = source
        self.aliases = {}
        self.class_outer = None
        self.report = {'app_servers': [], 'environment': [], 'unknowns': []}
        self.seen = set()

    def add(self, category, line, **fields):
        row = {'source': self.source, 'line': line, **fields}
        key = (category, tuple(sorted(row.items())))
        if key not in self.seen:
            self.seen.add(key)
            self.report[category].append(row)

    def unknown(self, node, detail):
        self.add('unknowns', node.lineno, detail=detail)

    def resolve(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return base + '.' + node.attr if base else None
        return None

    def bind(self, target, value=None):
        for name in _targets(target):
            if value:
                self.aliases[name] = value
            else:
                self.aliases.pop(name, None)
        if isinstance(target, ast.Attribute):
            # A mutation of an imported module's attributes invalidates proof.
            root = target
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                self.aliases.pop(root.id, None)

    def visit_Import(self, node):
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]

    def visit_ImportFrom(self, node):
        if any(alias.name == '*' for alias in node.names):
            self.aliases.clear()
            self.unknown(node, 'Wildcard import may replace source bindings; aliases unknown.')
            return
        for alias in node.names:
            name = alias.asname or alias.name
            if node.level or alias.name == '*' or not node.module:
                self.aliases.pop(name, None)
            else:
                self.aliases[name] = node.module + '.' + alias.name

    def visit_Assign(self, node):
        self.visit(node.value)
        value = self.resolve(node.value)
        for target in node.targets:
            self.bind(target, value if isinstance(target, ast.Name) else None)

    def visit_AnnAssign(self, node):
        self.visit(node.annotation)
        if node.value:
            self.visit(node.value)
        self.bind(node.target, self.resolve(node.value) if node.value else None)

    def visit_AugAssign(self, node):
        self.visit(node.value)
        self.bind(node.target)

    def visit_NamedExpr(self, node):
        self.visit(node.value)
        self.bind(node.target, self.resolve(node.value))

    def visit_Delete(self, node):
        for target in node.targets:
            self.bind(target)

    def literal_env(self, node, key, access):
        if (isinstance(key, ast.Constant) and isinstance(key.value, str)
                and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', key.value)):
            self.add('environment', node.lineno, name=key.value, access=access)
        else:
            self.unknown(node, 'Environment read has no supported literal name; value/default omitted.')

    def visit_Subscript(self, node):
        if isinstance(node.ctx, ast.Load) and self.resolve(node.value) == 'os.environ':
            self.literal_env(node, node.slice, 'os.environ[]')
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self.resolve(node.func)
        if name in {'os.getenv', 'os.environ.get'}:
            key = node.args[0] if node.args else next((item.value for item in node.keywords if item.arg == 'key'), None)
            self.literal_env(node, key, name)
        elif name in _HTTP_SERVERS or name == _WSGI:
            self.add('app_servers', node.lineno, name=name,
                     detail='Supported stdlib HTTP constructor/call; static evidence, not runtime verification.')
        elif name in _SOCKET_SERVERS:
            handler = node.args[1] if len(node.args) > 1 else next((item.value for item in node.keywords if item.arg == 'RequestHandlerClass'), None)
            if self.resolve(handler) in _HTTP_HANDLERS | {_HANDLER}:
                self.add('app_servers', node.lineno, name=name,
                         detail='Socket server uses a statically recognized HTTP handler; runtime unverified.')
            else:
                self.unknown(node, 'Generic socket server has no proven HTTP handler; HTTP semantics unknown.')
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for value in (*node.args.defaults, *node.args.kw_defaults):
            if value:
                self.visit(value)
        if node.returns:
            self.visit(node.returns)
        self.aliases.pop(node.name, None)
        outer = self.aliases
        inherited = self.class_outer if self.class_outer is not None else outer
        local = dict(inherited)
        bindings = _Bindings()
        for statement in node.body:
            bindings.visit(statement)
        for name in bindings.names - bindings.globals:
            local.pop(name, None)
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        if node.args.vararg:
            arguments.append(node.args.vararg)
        if node.args.kwarg:
            arguments.append(node.args.kwarg)
        for argument in arguments:
            local.pop(argument.arg, None)
        saved_class = self.class_outer
        self.aliases = local
        self.class_outer = None
        for statement in node.body:
            self.visit(statement)
        self.aliases = outer
        self.class_outer = saved_class

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node):
        for value in (*node.args.defaults, *node.args.kw_defaults):
            if value:
                self.visit(value)
        outer, saved_class = self.aliases, self.class_outer
        self.aliases = dict(saved_class if saved_class is not None else outer)
        self.class_outer = None
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.aliases.pop(arg.arg, None)
        if node.args.vararg:
            self.aliases.pop(node.args.vararg.arg, None)
        if node.args.kwarg:
            self.aliases.pop(node.args.kwarg.arg, None)
        self.visit(node.body)
        self.aliases, self.class_outer = outer, saved_class

    def visit_ClassDef(self, node):
        bases = [self.resolve(base) for base in node.bases]
        for value in (*node.bases, *node.decorator_list):
            self.visit(value)
        outer, saved_class = self.aliases, self.class_outer
        self.class_outer = outer if saved_class is None else saved_class
        self.aliases = dict(saved_class if saved_class is not None else outer)
        for statement in node.body:
            self.visit(statement)
        self.aliases, self.class_outer = outer, saved_class
        recognized = next((name for name in bases if name in _HTTP_SERVERS | _SOCKET_SERVERS), None)
        if any(name in _HTTP_HANDLERS | {_HANDLER} for name in bases):
            recognized = _HANDLER
        if recognized and not node.decorator_list:
            self.aliases[node.name] = recognized
        else:
            self.aliases.pop(node.name, None)

    def visit_If(self, node):
        self.visit(node.test)
        original = dict(self.aliases)
        branches = []
        for statements in (node.body, node.orelse):
            self.aliases = dict(original)
            for statement in statements:
                self.visit(statement)
            branches.append(self.aliases)
        self.aliases = {key:value for key,value in branches[0].items() if branches[1].get(key) == value}

    def visit_ExceptHandler(self, node):
        if node.type:
            self.visit(node.type)
        if node.name:
            self.aliases.pop(node.name, None)
        for statement in node.body:
            self.visit(statement)
        if node.name:
            self.aliases.pop(node.name, None)

    def visit_Try(self, node):
        original = dict(self.aliases)
        for statement in node.body:
            self.visit(statement)
        successful = dict(self.aliases)
        for statement in node.orelse:
            self.visit(statement)
        branches = [self.aliases]
        for handler in node.handlers:
            # The exception can occur at any earlier statement. Only bindings
            # unchanged across the body are established at the handler entry.
            self.aliases = {key:value for key,value in original.items()
                            if successful.get(key) == value}
            self.visit(handler)
            branches.append(self.aliases)
        first = branches[0]
        self.aliases = {key:value for key,value in first.items()
                        if all(branch.get(key) == value for branch in branches[1:])}
        for statement in node.finalbody:
            self.visit(statement)

    visit_TryStar = visit_Try

    def visit_Match(self, node):
        self.visit(node.subject)
        # Pattern capture has version-dependent binding semantics. Avoid
        # attributing any inherited alias to a pattern-bound identifier.
        self.aliases.clear()
        self.unknown(node, 'Pattern matching bindings are unsupported; inherited aliases unknown.')
        for case in node.cases:
            self.aliases.clear()
            if case.guard:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
        self.aliases.clear()

    def visit_For(self, node):
        self.visit(node.iter)
        original = dict(self.aliases)
        self.bind(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        self.aliases = {key:value for key,value in original.items() if self.aliases.get(key) == value}

    visit_AsyncFor = visit_For

    def visit_While(self, node):
        self.visit(node.test)
        original = dict(self.aliases)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)
        self.aliases = {key:value for key,value in original.items() if self.aliases.get(key) == value}

    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self.bind(item.optional_vars)
        for statement in node.body:
            self.visit(statement)

    visit_AsyncWith = visit_With

    def comprehension(self, node):
        outer = self.aliases
        self.aliases = dict(outer)
        for generator in node.generators:
            self.visit(generator.iter)
            self.bind(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        if isinstance(node, ast.DictComp):
            self.visit(node.key)
            self.visit(node.value)
        else:
            self.visit(node.elt)
        self.aliases = outer
        for child in ast.walk(node):
            if isinstance(child, ast.NamedExpr):
                self.bind(child.target)

    visit_ListComp = comprehension
    visit_SetComp = comprehension
    visit_DictComp = comprehension
    visit_GeneratorExp = comprehension


def discover_python(text, source):
    """Return app_servers/environment/unknowns, with no snippets or default values.

    This recognizes direct imports/aliases and literal environment names. Dynamic
    import, mutation, factory indirection and unsupported syntax remain unknown;
    it neither runs project code nor proves that an imported symbol is genuine.
    """
    empty = {'app_servers': [], 'environment': [], 'unknowns': []}
    def unsupported(detail, line=1):
        empty['unknowns'].append({'source': source, 'line': line, 'detail': detail})
        return empty
    if not isinstance(text, str):
        return unsupported('Python source must be bounded text; not inspected.')
    try:
        if len(text.encode('utf-8')) > _MAX_BYTES:
            return unsupported('Python source exceeds 1 MiB inspection budget.')
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, UnicodeError):
        return unsupported('Python syntax could not be safely parsed; evidence unknown.')
    nodes = [(tree, 0)]
    count = 0
    while nodes:
        node, depth = nodes.pop()
        count += 1
        if count > _MAX_NODES or depth > _MAX_DEPTH:
            return unsupported('Python AST exceeds bounded node/depth inspection budget.')
        nodes.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    inspector = _Evidence(source)
    inspector.visit(tree)
    return inspector.report
