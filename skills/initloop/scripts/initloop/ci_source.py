"""Read a small literal GitHub Actions subset; never evaluate or run a workflow.

Locations lead an agent back to source. This is not YAML or shell interpretation,
workflow validation, permission to install tools, or proof that commands work.
"""
import posixpath
import re
import shlex

_LIMIT = 'Literal GitHub Actions subset only (64 mapping levels, 4096 nodes); ambiguous or malformed workflows yield no resolved observations. Expressions and shell state require source inspection.'
_SECRET = re.compile(r'(^|/)(?:\.env(?:\.|$)|[^/]*(?:secret|credential)[^/]*|[^/]*\.(?:key|pem))', re.I)


def _literal(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    if any(c in value for c in '$`\\{}&*!\n\r'):
        return None
    return value


def _path(value, cwd='.'):
    value = _literal(value)
    if value is None or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', value) or value.startswith('/'):
        return None
    target = posixpath.normpath(posixpath.join(cwd, value))
    if target == '..' or target.startswith('../') or _SECRET.search(target):
        return None
    return target


def _nodes(text):
    """Only mapping keys, sequence mapping items and literal blocks are recognized."""
    root = {'children': [], 'line': 1, 'key': '', 'value': ''}
    stack = [(-1, root)]
    lines = text.splitlines()
    i = 0
    count = 0
    while i < len(lines):
        content = lines[i]; number = i + 1; i += 1
        if not content.strip() or content.lstrip().startswith('#'):
            continue
        if '\t' in content[:len(content)-len(content.lstrip())]:
            root.setdefault('invalid', []).append(number)
            continue
        if len(stack) > 64 or count >= 4096:
            root.setdefault('invalid', []).append(number)
            break
        indent = len(content)-len(content.lstrip())
        while stack[-1][0] >= indent:
            stack.pop()
        item = content.strip()
        if item.startswith('- '):
            step = {'key': '__item__', 'value': '', 'line': number, 'children': []}
            stack[-1][1]['children'].append(step)
            count += 1
            if count >= 4096:
                root.setdefault('invalid', []).append(number)
                break
            stack.append((indent, step))
            indent += 2; item = item[2:]
        match = re.match(r'([A-Za-z0-9_.-]+):(?:\s+(.*)|\s*)$', item)
        if not match:
            root.setdefault('invalid', []).append(number)
            continue
        keys = stack[-1][1].setdefault('_keys', set())
        if match[1] in keys:
            root.setdefault('invalid', []).append(number)
        keys.add(match[1])
        count += 1
        node = {'key': match[1], 'value': match[2] or '', 'line': number, 'children': []}
        stack[-1][1]['children'].append(node)
        stack.append((indent, node))
        if node['value'] in {'|', '|-', '|+', '>', '>-', '>+'}:
            block = []
            while i < len(lines) and (not lines[i].strip() or len(lines[i])-len(lines[i].lstrip()) > indent):
                block.append((i+1, lines[i].strip())); i += 1
            node['block'] = block
    return root


def _child(node, key):
    return next((x for x in node['children'] if x['key'] == key), None)


def discover_ci(files):
    """Return declarations plus explicit uncertainty from sanitized source bytes.

    No raw run bodies, environment values, action/job names or arbitrary image
    registry names enter output. Existing paths prove presence, never correctness.
    """
    result = {'workflows': [], 'unknowns': []}
    for source, raw in sorted(files.items()):
        github = bool(re.fullmatch(r'\.github/workflows/[^/]+\.ya?ml', source))
        if not github:
            if source in {'.gitlab-ci.yml', '.gitlab-ci.yaml', 'Jenkinsfile', 'azure-pipelines.yml', '.circleci/config.yml'}:
                result['unknowns'].append({'source': source, 'line': 1, 'state': 'inferred',
                    'runtime_verified': False, 'detail': 'CI format not statically supported; inspect source.'})
            continue
        text = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else str(raw)
        tree = _nodes(text)
        flow = {'source': source, 'line': 1, 'state': 'declared', 'runtime_verified': False,
                'format': 'github_actions_subset', 'observations': [], 'limitations': [_LIMIT]}
        result['workflows'].append(flow)

        def unknown(line, detail):
            row = {'source': source, 'line': line, 'state': 'inferred', 'runtime_verified': False, 'detail': detail}
            if row not in result['unknowns']:
                result['unknowns'].append(row)

        def observe(kind, line, **values):
            flow['observations'].append({'kind': kind, 'source': source, 'line': line,
                'state': 'declared', 'status': 'declared_unverified', 'runtime_verified': False, **values})

        def exists(path):
            return path == '.' or path in files or any(x.startswith(path.rstrip('/')+'/') for x in files)

        def target(kind, node, value, cwd='.'):
            path = _path(value, cwd) if cwd is not None else None
            if path is None:
                unknown(node['line'], 'Dynamic, sensitive or unsupported path; target unresolved.')
                return None
            found = exists(path)
            observe(kind, node['line'], target=path, exists=found)
            if not found:
                unknown(node['line'], 'Referenced path absent from sanitized inputs; stale, generated or excluded target remains unknown.')
            return path

        def cwd_default(node, inherited):
            defaults = _child(node, 'defaults')
            if defaults is None:
                return inherited
            if defaults['value']:
                unknown(defaults['line'], 'Dynamic or unsupported defaults; working directory unresolved.')
                return None
            run = _child(defaults, 'run')
            if run and run['value']:
                unknown(run['line'], 'Dynamic or unsupported run defaults; working directory unresolved.')
                return None
            where = _child(run, 'working-directory') if run else None
            return target('working_directory', where, where['value']) if where else inherited

        if tree.get('invalid'):
            for line in tree['invalid']:
                unknown(line, 'Duplicate, merge, unsupported structure or parser bound; entire workflow resolution withheld.')
            continue
        pending = [tree]
        while pending:
            node = pending.pop()
            if node['key'] in {'matrix', 'strategy'} or '${{' in node['value'] or node['value'].startswith(('&', '*')):
                unknown(node['line'], 'Expression, matrix or YAML indirection unsupported; no resolved value inferred.')
            pending.extend(reversed(node['children']))
        default = cwd_default(tree, '.')
        jobs = _child(tree, 'jobs')
        if jobs is None or jobs['value']:
            unknown(1, 'Literal jobs mapping unavailable; inspect workflow manually.')
            continue
        for job in jobs['children']:
            if _child(job, 'uses'):
                unknown(_child(job, 'uses')['line'], 'Reusable workflow not resolved or executed.')
            job_cwd = cwd_default(job, default)
            environment = _child(job, 'environment')
            production = bool(environment and re.search(r'prod|release|publish|deploy', environment['value'], re.I))
            services = _child(job, 'services')
            for service in services['children'] if services else []:
                image = _child(service, 'image')
                if image:
                    match = re.fullmatch(r'(python|node|postgres|mysql|mariadb|redis|mongo|rabbitmq):([0-9][A-Za-z0-9_.-]{0,60})', _literal(image['value']) or '')
                    if match:
                        observe('service', image['line'], image=match[0])
                    else:
                        unknown(image['line'], 'Service image unresolved or outside bounded public-image support.')
            steps = _child(job, 'steps')
            for step in steps['children'] if steps else []:
                where = _child(step, 'working-directory')
                cwd = target('working_directory', where, where['value']) if where else job_cwd
                run = _child(step, 'run'); name = _child(step, 'name')
                prod_step = production or bool(name and re.search(r'deploy|publish|release', name['value'], re.I))
                if run:
                    if run['value'].startswith('>'):
                        unknown(run['line'], 'Folded run block unsupported; shell commands unresolved.')
                    else:
                        for line, command in run.get('block', [(run['line'], run['value'])]):
                            if not command or command.startswith('#'):
                                continue
                            try: words = shlex.split(command)
                            except ValueError:
                                unknown(line, 'Shell syntax unsupported; command unresolved.'); continue
                            normalized = category = script = None
                            if words and words[0] in {'python', 'python3'}:
                                if len(words) >= 3 and words[1] == '-m' and words[2] in {'unittest', 'pytest', 'compileall', 'build'}:
                                    normalized = 'python -m '+words[2]
                                    category = 'test' if words[2] in {'unittest', 'pytest'} else 'build'
                                elif len(words) >= 2 and words[1].endswith('.py'):
                                    normalized, category, script = 'python script', 'inspect_script', words[1]
                                    prod_step = prod_step or bool(re.fullmatch(r'(?:deploy|publish|release)(?:[-_][A-Za-z0-9_-]+)?\.py', posixpath.basename(script)))
                            elif words and words[0] in {'npm', 'pnpm', 'yarn'} and len(words) >= 3 and words[1] == 'run':
                                normalized, category = words[0]+' run', 'inspect_script'
                                prod_step = prod_step or words[2] in {'deploy', 'publish', 'release'}
                            elif words and words[0] == 'make':
                                normalized, category = 'make target', 'inspect_target'
                                prod_step = prod_step or any(re.fullmatch(r'(?:deploy|publish|release)(?:[-_][A-Za-z0-9_-]+)?', word) for word in words[1:])
                            if normalized:
                                observe('command', line, command=normalized, category=category, cwd=cwd,
                                    local_appropriateness='production_only' if prod_step else 'requires_review')
                                if script and cwd is not None:
                                    target('script', {'line': line}, script, cwd)
                            else:
                                unknown(line, 'Run command outside bounded static support; inspect without executing.')
                            # A shell statement can alter subsequent resolution; do not interpret it.
                            if (words and words[0] in {'cd', 'pushd', 'popd'}) or re.search(r'[;&|`]|\$\(', command):
                                cwd = None
                                unknown(line, 'Shell state or composition unsupported; subsequent working directory unresolved.')
                uses = _child(step, 'uses')
                options = _child(step, 'with')
                if uses and not re.fullmatch(r'actions/(?:setup-python|setup-node|setup-go|upload-artifact|checkout)@[A-Za-z0-9_.-]+', uses['value']):
                    unknown(uses['line'], 'Action reference outside bounded static support; inspect source without executing.')
                if uses and options:
                    action = uses['value']
                    for family, field, runtime in (('setup-python','python-version','python'), ('setup-node','node-version','node'), ('setup-go','go-version','go')):
                        if re.fullmatch('actions/'+family+r'@[A-Za-z0-9_.-]+', action):
                            version = _child(options, field)
                            if version:
                                literal = _literal(version['value'])
                                if literal and re.fullmatch(r'[0-9][0-9.x*-]{0,40}', literal):
                                    observe('runtime', version['line'], name=runtime, version=literal)
                                else:
                                    unknown(version['line'], 'Runtime version dynamic or unsupported; unresolved.')
                    if re.fullmatch(r'actions/upload-artifact@[A-Za-z0-9_.-]+', action):
                        artifact = _child(options, 'path')
                        if artifact:
                            for line, value in artifact.get('block', [(artifact['line'], artifact['value'])]):
                                if value:
                                    target('artifact', {'line': line}, value)
    return result
