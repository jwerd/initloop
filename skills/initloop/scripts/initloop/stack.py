"""Bounded, evidence-based stack discovery. Never executes project or runner code.

This deliberately is not a YAML/TOML interpreter: unsupported syntax remains unknown.
Values and free-form command contents are not copied into the report.
"""
import io
import json
import re
import shlex
import tokenize
from pathlib import Path


# A client package indicates a possible dependency, not an available server.
_PACKAGES = {
    'fastapi': ('frameworks', 'fastapi'), 'flask': ('frameworks', 'flask'),
    'django': ('frameworks', 'django'), 'express': ('frameworks', 'express'),
    'fastify': ('frameworks', 'fastify'), 'next': ('frameworks', 'next.js'),
    'laravel/framework': ('frameworks', 'laravel'), 'symfony/framework-bundle': ('frameworks', 'symfony'),
    'uvicorn': ('app_servers', 'uvicorn'), 'gunicorn': ('app_servers', 'gunicorn'),
    'hypercorn': ('app_servers', 'hypercorn'), 'puma': ('app_servers', 'puma'),
    'psycopg': ('databases', 'postgresql'), 'psycopg2': ('databases', 'postgresql'),
    'psycopg2-binary': ('databases', 'postgresql'), 'asyncpg': ('databases', 'postgresql'),
    'pg': ('databases', 'postgresql'), 'mysql2': ('databases', 'mysql'),
    'pymysql': ('databases', 'mysql'), 'mysqlclient': ('databases', 'mysql'),
    'pymongo': ('databases', 'mongodb'), 'mongodb': ('databases', 'mongodb'),
    'better-sqlite3': ('databases', 'sqlite'), 'sqlite3': ('databases', 'sqlite'),
    'redis': ('caches', 'redis'), 'ioredis': ('caches', 'redis'),
    'celery': ('queues', 'celery'), 'rq': ('queues', 'rq'), 'bullmq': ('queues', 'bullmq'),
    'github.com/redis/go-redis/v9': ('caches', 'redis'),
    'github.com/jackc/pgx/v5': ('databases', 'postgresql'),
}
_IMAGES = {'python': ('runtimes', 'python'), 'node': ('runtimes', 'node'),
           'php': ('runtimes', 'php'), 'golang': ('runtimes', 'go'),
           'postgres': ('databases', 'postgresql'), 'mysql': ('databases', 'mysql'),
           'mariadb': ('databases', 'mariadb'), 'mongo': ('databases', 'mongodb'),
           'redis': ('caches', 'redis'), 'rabbitmq': ('queues', 'rabbitmq'),
           'nginx': ('app_servers', 'nginx'), 'httpd': ('app_servers', 'apache')}
_COMPOSE = {'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'}
_FIELDS = ('runtimes', 'frameworks', 'app_servers', 'databases', 'caches', 'queues', 'workers', 'apis')


def _json(raw):
    try:
        result = json.loads(raw)
        return result if isinstance(result, dict) else {}
    except (ValueError, UnicodeError):
        return {}


def _version(value):
    """Version evidence only, never arbitrary manifest/config values or direct URLs."""
    if not isinstance(value, str) or not re.search(r'\d', value):
        return None
    if len(value) <= 80 and re.fullmatch(r'[vV0-9.*^~<>=!|, +/_-]+(?:[a-zA-Z]+[0-9.-]*)?', value):
        return value
    return None


def _line(text, needle):
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 1


def _safe_name(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_@./:-]{1,120}', value)


def _python_configuration_names(text, reads):
    """Real identifier tokens plus AST-proven env names; never string defaults."""
    identifiers = set()
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.ERRORTOKEN and not token.string.isspace():
                identifiers.clear()
                break
            if token.type == tokenize.NAME:
                identifiers.add((token.start[0], token.string))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        identifiers.clear()
    identifiers.update((row['line'], row['name']) for row in reads)
    return identifiers


def configuration_resources(stack):
    """Names and locations only; values/defaults never enter dependency evidence."""
    rows = []
    for item in stack.get('environment_evidence', []):
        key = item['name']
        kind = next((kind for kind, pattern in (
            ('database', r'DB|DATABASE'), ('queue', r'QUEUE|BROKER'),
            ('cache', r'REDIS|CACHE'), ('storage', r'S3|STORAGE|BUCKET'),
            ('identity', r'OAUTH|AUTH|OIDC'), ('mail', r'MAIL|SMTP'),
            ('api', r'API|URL|ENDPOINT')) if re.search(pattern, key, re.I)), None)
        if kind:
            rows.append({'kind': kind, 'configuration': key, 'source': item['source'],
                         'line': item['line'], 'state': 'inferred',
                         'strategy': 'needs contract inspection', 'workflows': []})
    return rows


def discover(root, files=None, scan_metadata=None):
    """Return static stack evidence and runner choices; all runtime observations unknown.

    files may be the sanitized relative-path/bytes map from workflow._files. When
    omitted that scanner is imported lazily so workflow can call us without a cycle.
    """
    if files is None:
        from .readonly_scan import scan
        files, scan_metadata = scan(root)
    report = {'schema_version': 1, **{key: [] for key in _FIELDS},
              'runners': [], 'services': [], 'relationships': [], 'unknowns': [], 'conflicts': [],
              'contracts': [], 'environment_evidence': [], 'environment_names': []}
    if scan_metadata is not None:
        report['discovery_scan'] = scan_metadata
    seen = set()
    database_rows = {}

    def fact(group, name, version, source, line=1, kind='declared', **extra):
        value = {'name': name, 'version': _version(version), 'version_kind': kind,
                 'source': source, 'line': line,
                 'evidence': {'source': source, 'line': line, 'kind': kind},
                 'runtime_observed': None, **extra}
        if group == 'databases':
            # Merge repeated references only when every semantic field matches.
            # Configuration/service/client/version fields keep connections distinct.
            identity = {key: item for key, item in value.items() if key not in {'line', 'evidence'}}
            key = json.dumps(identity, sort_keys=True)
            if key in database_rows:
                row = database_rows[key]
                row['lines'] = sorted(set(row['lines'] + [line]))
                row['evidence']['lines'] = row['lines']
                return
            value['lines'] = [line]
            value['evidence']['lines'] = [line]
            database_rows[key] = value
        key = json.dumps([group, value], sort_keys=True)
        if key not in seen:
            report[group].append(value)
            seen.add(key)

    def package(name, version, source, text, kind='declared'):
        key = name.lower().replace('_', '-')
        if key in _PACKAGES:
            group, label = _PACKAGES[key]
            extra = {}
            if group in {'databases', 'caches'}:
                # Package versions must not masquerade as database server versions.
                extra = {'client_package': key, 'client_version': _version(version),
                         'detail': 'Client dependency; server version, location and access remain unknown.'}
                version = None
            fact(group, label, version, source, _line(text, name), kind, **extra)

    def runner(kind, source, line=1, command=None, **extra):
        row = {'kind': kind, 'source': source, 'line': line,
               'scope': Path(source).parent.as_posix(), 'status': 'declared_unverified', **extra}
        if command:
            row['command'] = command
        if row not in report['runners']:
            report['runners'].append(row)

    def image(value, source, line, service=None):
        # Report only recognized official image family + a version-shaped tag.
        match = re.fullmatch(r'(?:docker\.io/library/)?([a-z0-9-]+)(?::([^\s@]+))?(?:@sha256:[0-9a-f]{64})?', value.strip('"\''))
        if not match or match.group(1) not in _IMAGES:
            return None, None
        group, label = _IMAGES[match.group(1)]
        tag = match.group(2)
        numeric = re.match(r'(\d+(?:\.\d+)*)', tag or '')
        version = numeric.group(1) if numeric else None
        fact(group, label, version, source, line, **({'service': service} if service else {}))
        safe_tag = tag if tag and re.fullmatch(r'[0-9][A-Za-z0-9_.-]{0,60}', tag) else None
        return match.group(1) + (':' + safe_tag if safe_tag else ''), version

    for source, raw in sorted(files.items()):
        text = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else str(raw)
        path, name = Path(source), Path(source).name
        contract = None
        configuration_names = None
        if path.suffix.lower() == '.py':
            from .python_source import discover_python
            python = discover_python(text, source)
            for server in python['app_servers']:
                fact('app_servers', server['name'], None, source, server['line'],
                     detail=server.get('detail', 'Static Python HTTP constructor reference; runtime unverified.'))
            report['environment_evidence'].extend(python['environment'])
            report['unknowns'].extend(python['unknowns'])
            configuration_names = _python_configuration_names(text, python['environment'])
        if name in {'.env.example', '.env.sample', '.env.template'}:
            configuration_names = set()
            for line, content in enumerate(text.splitlines(), 1):
                match = re.match(r'\s*([A-Z][A-Z0-9_]*)\s*=', content)
                if match:
                    configuration_names.add((line, match.group(1)))
                    report['environment_evidence'].append({'name': match.group(1), 'source': source,
                                                           'line': line, 'access': 'template declaration'})
        if path.suffix.lower() in {'.json', '.yaml', '.yml'}:
            from .contracts import discover_contract
            contract = discover_contract(text, source)
            if contract:
                report['contracts'].append(contract)
                fact('apis', contract['name'], contract.get('version'), source, contract.get('line', 1),
                     operations=contract['operations'], contract_status=contract['status'],
                     detail='Contract declaration only; request/response behavior and access unverified.')
                for detail in contract.get('limitations', []):
                    report['unknowns'].append({'source': source, 'line': contract.get('line', 1), 'detail': detail})
        if name == 'package.json':
            doc = _json(text)
            fact('runtimes', 'node', doc.get('engines', {}).get('node') if isinstance(doc.get('engines'), dict) else None, source,
                 _line(text, 'engines'))
            for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                deps = doc.get(section, {})
                if isinstance(deps, dict):
                    for dependency, version in deps.items():
                        package(dependency, version, source, text)
            scripts = doc.get('scripts', {})
            if isinstance(scripts, dict):
                for script in sorted(scripts):
                    if _safe_name(script):
                        runner('manifest-script', source, _line(text, '"' + script + '"'), 'npm run ' + script)
        elif name == 'package-lock.json':
            doc = _json(text)
            packages = doc.get('packages', {})
            if isinstance(packages, dict):
                for location, item in packages.items():
                    if isinstance(item, dict) and 'node_modules/' in location:
                        package(location.rsplit('node_modules/', 1)[1], item.get('version'), source, text, 'resolved')
            # npm lock v1.
            deps = doc.get('dependencies', {})
            if isinstance(deps, dict):
                for dependency, item in deps.items():
                    if isinstance(item, dict):
                        package(dependency, item.get('version'), source, text, 'resolved')
        elif name == 'composer.json':
            doc = _json(text)
            deps = doc.get('require', {})
            if isinstance(deps, dict):
                fact('runtimes', 'php', deps.get('php'), source, _line(text, '"php"'))
                for dependency, version in deps.items():
                    package(dependency, version, source, text)
            scripts = doc.get('scripts', {})
            if isinstance(scripts, dict):
                for script in sorted(scripts):
                    if _safe_name(script):
                        runner('manifest-script', source, _line(text, '"' + script + '"'), 'composer run-script ' + script)
        elif name == 'composer.lock':
            doc = _json(text)
            for section in ('packages', 'packages-dev'):
                packages = doc.get(section, [])
                if isinstance(packages, list):
                    for item in packages:
                        if isinstance(item, dict) and isinstance(item.get('name'), str):
                            package(item['name'], item.get('version'), source, text, 'resolved')
        elif name in {'pyproject.toml', 'requirements.txt', 'requirements-dev.txt', 'Pipfile', 'setup.cfg', 'setup.py'}:
            match = re.search(r'(?:requires-python|python_requires)\s*=\s*["\']([^"\']+)', text)
            fact('runtimes', 'python', match.group(1) if match else None, source,
                 _line(text, match.group(0)) if match else 1)
            for dependency in re.finditer(r'(?:^|[\s"\'\[,])([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*((?:[<>=!~^]+\s*[0-9][A-Za-z0-9.*,+<>=!~^-]*)?)', text, re.M):
                package(dependency.group(1), dependency.group(2).strip(), source, text)
            if name == 'pyproject.toml':
                section = re.search(r'^\[project\.scripts\]\s*$(.*?)(?=^\[|\Z)', text, re.M | re.S)
                if section:
                    for script in re.findall(r'^([A-Za-z0-9_.-]+)\s*=', section.group(1), re.M):
                        runner('manifest-script', source, _line(text, script + ' '), script)
        elif name in {'uv.lock', 'poetry.lock'}:
            for block in re.finditer(r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', text, re.S):
                n = re.search(r'^name\s*=\s*"([^"\n]+)"', block.group(1), re.M)
                v = re.search(r'^version\s*=\s*"([^"\n]+)"', block.group(1), re.M)
                if n and v:
                    package(n.group(1), v.group(1), source, text, 'resolved')
        elif name == 'go.mod':
            match = re.search(r'^go\s+(\S+)', text, re.M)
            fact('runtimes', 'go', match.group(1) if match else None, source,
                 _line(text, match.group(0)) if match else 1)
            for match in re.finditer(r'^\s*(?:require\s+)?(github\.com/[A-Za-z0-9_./-]+)\s+(v[0-9][A-Za-z0-9_.+-]*)', text, re.M):
                package(match.group(1), match.group(2), source, text, 'resolved')
        elif name in {'.python-version', '.nvmrc', '.node-version', '.ruby-version', 'runtime.txt'}:
            runtime = {'.python-version': 'python', '.nvmrc': 'node', '.node-version': 'node', '.ruby-version': 'ruby'}.get(name)
            value = text.strip()
            if name == 'runtime.txt' and value.startswith('python-'):
                runtime, value = 'python', value[7:]
            if runtime:
                fact('runtimes', runtime, value, source)
        elif name == '.tool-versions':
            for lineno, line in enumerate(text.splitlines(), 1):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in {'python', 'nodejs', 'ruby', 'golang'}:
                    fact('runtimes', {'nodejs': 'node', 'golang': 'go'}.get(parts[0], parts[0]), parts[1], source, lineno)

        if name == 'Dockerfile' or name.startswith('Dockerfile.'):
            runner('container', source)
            for lineno, line in enumerate(text.splitlines(), 1):
                match = re.match(r'\s*FROM\s+(?:--platform=\S+\s+)?(\S+)', line, re.I)
                if match:
                    image(match.group(1), source, lineno)
                for server in ('uvicorn', 'gunicorn', 'nginx'):
                    if re.search(r'\b' + server + r'\b', line):
                        fact('app_servers', server, None, source, lineno)

        if name in _COMPOSE:
            runner('compose', source, command='docker compose -f ' + shlex.quote(source) + ' up', scope='.')
            _compose(text, source, report, fact, image)
        if name == 'Makefile':
            for lineno, line in enumerate(text.splitlines(), 1):
                match = re.match(r'^([A-Za-z0-9_.-]+):(?:[^=]|$)', line)
                if match and not match.group(1).startswith('.'):
                    runner('native-script', source, lineno, 'make ' + match.group(1))
        if name == 'Procfile' or name.startswith('Procfile.'):
            runner('native-script', source, command='foreman start -f ' + shlex.quote(source), scope='.')
            for lineno, line in enumerate(text.splitlines(), 1):
                match = re.match(r'^([A-Za-z0-9_-]+):', line)
                if match and re.search(r'worker|queue|celery|rq\b', line, re.I):
                    fact('workers', match.group(1), None, source, lineno)
        if name in {'dev', 'dev.sh', 'start.sh', 'serve.sh'} or (path.parent.name in {'scripts', 'bin'} and name.endswith('.sh')):
            runner('native-script', source, command='sh ' + shlex.quote(source), scope='.')
        if path.suffix.lower() in {'.md', '.rst'}:
            for lineno, line in enumerate(text.splitlines(), 1):
                if re.search(r'\b(?:python(?:3)?\s+-m\s+|npm\s+(?:run\s+)?(?:start|dev)|uvicorn\s+|docker\s+compose\s+|make\s+(?:start|dev|serve))', line):
                    runner('documented-command', source, lineno, detail='Read the referenced command in context; arguments are not copied.')

        # Contracts have their own bounded evidence reader. Examples/defaults are
        # not source configuration references, even if they contain uppercase keys.
        if contract:
            continue

        # Configuration names are evidence; values (including URLs) stay private.
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in re.finditer(r'\b([A-Z][A-Z0-9_]*)\b', line):
                key = match.group(1)
                if configuration_names is not None and (lineno, key) not in configuration_names:
                    continue
                if not re.search(r'(?:DATABASE_URL|DATABASE_DSN|DB_DSN|DB_HOST|DB_CONNECTION|REDIS_URL|CACHE_URL|QUEUE_CONNECTION|BROKER_URL|_URL|_ENDPOINT)$', key):
                    continue
                group = 'databases' if re.search('DATABASE|DB_', key) else 'caches' if re.search('REDIS|CACHE', key) else 'queues' if re.search('QUEUE|BROKER', key) else 'apis'
                fact(group, key, None, source, lineno, configuration=key,
                     detail='Configuration reference; target, server version and connectivity are unverified.')
                if key.endswith('DB_CONNECTION'):
                    driver = re.search(r'=\s*[\"\']?(postgresql|postgres|pgsql|mysql|sqlite|mongodb)\b', line)
                    if driver:
                        engine = {'postgres': 'postgresql', 'pgsql': 'postgresql'}.get(driver.group(1), driver.group(1))
                        fact('databases', engine, None, source, lineno, configuration=key,
                             detail='Declared driver only; server version and access are unverified.')
            # Source consumer evidence: known client/module names without source snippets.
            if path.suffix in {'.py', '.ts', '.js', '.mjs', '.php', '.go'}:
                if re.search(r'\b(?:sqlite3|sqlite)\b', line):
                    fact('databases', 'sqlite', None, source, lineno, detail='Source reference; file path and runtime state unverified.')
                for server in ('uvicorn', 'gunicorn'):
                    if re.search(r'\b' + server + r'\b', line):
                        fact('app_servers', server, None, source, lineno)
                if re.search(r'\b(?:celery|rq|bullmq)\b', line, re.I):
                    fact('workers', 'worker', None, source, lineno, detail='Worker-related source; lifecycle requires inspection.')

    from .repository_evidence import discover_repository
    from .ci_source import discover_ci
    report['repository_evidence'] = discover_repository(files)
    ci = discover_ci(files)
    report['repository_evidence']['ci_workflows'] = ci['workflows']
    report['repository_evidence']['unknowns'].extend(ci['unknowns'])
    report['environment_names'] = sorted({row['name'] for row in report['environment_evidence']})

    # Only exact contradictory major declarations are flagged. Compatible ranges and
    # package-vs-server versions must not become false conflicts.
    runtime_groups = {}
    for row in report['runtimes']:
        value = row['version'] or ''
        if re.fullmatch(r'v?\d+(?:\.\d+)*', value):
            runtime_groups.setdefault(row['name'], []).append(row)
    for name, values in runtime_groups.items():
        # Different minor Python/PHP versions may matter; Node major is the compatibility boundary.
        width = 1 if name == 'node' else 2
        signatures = {tuple(x['version'].lstrip('v').split('.')[:width]) for x in values}
        if len(signatures) > 1:
            report['conflicts'].append({'name': name, 'versions': sorted({x['version'] for x in values}),
                                        'sources': sorted({x['source'] for x in values}),
                                        'detail': 'Different runtime declarations; resolve intended target before installation.'})

    existing = report['runners']
    preferred = sorted({x['source'] for x in existing if x['kind'] != 'container'})
    options = []
    if preferred:
        kinds = {'compose' if x['kind'] == 'compose' else 'native' for x in existing if x['kind'] != 'container'}
        for kind in sorted(kinds):
            options.append({'kind': kind, 'rationale': 'Existing repository runner evidence; inspect and try its published workflow first.',
                            'tradeoffs': 'Preserves project convention; installed tools, side effects and working behavior still require verification.'})
        reason = 'Preserve existing runners before proposing replacements; static presence does not prove they work.'
    else:
        options = [{'kind': 'native', 'rationale': 'Use the project runtime directly when available under harness/project permissions.',
                    'tradeoffs': 'Fast iteration and existing tools; host execution is not sandboxed and dependency/service setup may affect the host.'},
                   {'kind': 'compose', 'rationale': 'Consider isolated multi-service development when container tooling is available and appropriate.',
                    'tradeoffs': 'Repeatable service versions and owned data volumes; requires container tooling, image preparation and orchestration.'}]
        reason = 'No published runnable workflow established. Select a suitable supported runner after inspecting prerequisites.'
    report['runner_decision'] = {'status': 'existing_evidence' if preferred else 'choice_required',
                                 'preferred': preferred, 'options': options, 'reason': reason}
    report['unknowns'] += ['Installed/runtime-observed versions and service connectivity have not been checked.',
                          'Missing evidence is not evidence that an external service is unavailable.',
                          'Lifecycle, seed/reset safety, data persistence and local substitute fidelity require runtime validation.']
    if not preferred:
        report['unknowns'].append('Install/start/test/stop commands and the intended runner need confirmation.')
    report['limitations'] = ['Static bounded discovery; no commands, configuration interpolation or arbitrary parsers executed.',
                             'Evidence may omit dynamic configuration, includes, unusual syntax and unsupported lockfiles.',
                             'Dependency client versions do not establish server versions; no runtime observations are inferred.',
                             'Credential files and values are excluded; API URLs and command argument values are not copied.']
    return report


def _compose(text, source, report, fact, image):
    """Recognize conventional indented Compose service blocks without evaluating YAML."""
    in_services, current, section = False, None, None
    for lineno, line in enumerate(text.splitlines(), 1):
        if re.match(r'^services:\s*(?:#.*)?$', line):
            in_services, current, section = True, None, None
            continue
        if in_services and line and not line[0].isspace() and not line.startswith('#'):
            in_services, current = False, None
        if not in_services:
            continue
        match = re.match(r'^  ([A-Za-z0-9_.-]+):\s*(?:#.*)?$', line)
        if match:
            current = {'name': match.group(1), 'source': source, 'line': lineno,
                       'image': None, 'version': None, 'ports': [], 'storage': [], 'depends_on': [],
                       'status': 'declared_unverified'}
            report['services'].append(current)
            section = None
            if re.search('worker|queue|scheduler', current['name'], re.I):
                fact('workers', current['name'], None, source, lineno)
            continue
        if current is None:
            continue
        prop = re.match(r'^    ([A-Za-z_]+):\s*(.*?)\s*$', line)
        if prop:
            section, value = prop.groups()
            if section == 'image':
                current['image'], current['version'] = image(value, source, lineno, current['name'])
            if section == 'depends_on' and value.startswith('['):
                for dependency in re.findall(r'[A-Za-z0-9_.-]+', value):
                    _edge(report, current, dependency, source, lineno)
            continue
        if section == 'depends_on':
            dependency = re.match(r'^      (?:-\s*)?([A-Za-z0-9_.-]+):?\s*$', line)
            if dependency:
                _edge(report, current, dependency.group(1), source, lineno)
        if section in {'ports', 'volumes'}:
            item = re.match(r'^      -\s*["\']?([^"\'\s]+)', line)
            if not item:
                continue
            value = item.group(1)
            if section == 'ports' and re.fullmatch(r'[0-9.:/-]+', value):
                current['ports'].append(value)
            elif section == 'volumes':
                # Do not reveal arbitrary host paths; safe named volumes and targets only.
                volume = re.fullmatch(r'([A-Za-z0-9_-]+):(/[A-Za-z0-9_./-]+)(?::(?:ro|rw))?', value)
                if volume:
                    current['storage'].append(value)
                else:
                    current['storage'].append('mount declared; inspect source and ownership before use')


def _edge(report, current, dependency, source, line):
    if dependency not in current['depends_on']:
        current['depends_on'].append(dependency)
        report['relationships'].append({'from': current['name'], 'to': dependency,
                                        'kind': 'depends_on', 'source': source, 'line': line})
