"""Static instruction proposals. Never executes project code or applies a proposal."""
import hashlib
import json
import os
import re
import shlex
import subprocess
import stat
from pathlib import Path

_INSTRUCTIONS = {'AGENTS.md', 'CLAUDE.md'}


def _files(root):
    """Compatibility map-only wrapper; public discovery also reports scan limits."""
    from .readonly_scan import scan
    return scan(root)[0]


def _json(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError):
        return {}


def _safe_name(name):
    return isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_@./:-]{1,100}', name)



def _git_provenance(root, scan_metadata):
    """Query only an explicit non-link root marker, never an excluded/ancestor repo.

    A regular .git marker is the normal Git worktree mechanism. This guard does
    not change snapshot rules or reinterpret worktree metadata as application
    input. Ambient repository-location overrides are omitted for these queries.
    """
    result = {'revision': None, 'dirty': None,
              'provenance': {'status': 'unavailable', 'source': '.git'}}
    provenance = result['provenance']
    if any(row['source'] in {'.', '.git'} for row in scan_metadata['findings']):
        provenance['reason'] = 'metadata_excluded'
        return result
    try:
        mode = (root / '.git').lstat().st_mode
    except OSError as error:
        provenance['reason'] = 'metadata_absent' if isinstance(error, FileNotFoundError) else 'metadata_inaccessible'
        import errno
        provenance['errno'] = errno.errorcode.get(error.errno, 'UNKNOWN')
        return result
    if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        provenance['reason'] = 'metadata_excluded'
        return result
    names = {'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE',
             'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'}
    provenance['ambient_location_overrides_omitted'] = sorted(names & os.environ.keys())
    env = {key: value for key, value in os.environ.items() if key not in names}
    env['GIT_OPTIONAL_LOCKS'] = '0'
    command = ['git', '-c', 'core.fsmonitor=false', '-C', str(root)]
    try:
        head = subprocess.run(command + ['rev-parse', 'HEAD'], capture_output=True, text=True, timeout=5, env=env)
        if head.returncode != 0 or not re.fullmatch(r'[0-9a-f]{40,64}', head.stdout.strip()):
            provenance.update(reason='head_unavailable', exit_code=head.returncode)
            return result
        result['revision'] = head.stdout.strip()
        state = subprocess.run(command + ['status', '--porcelain'], capture_output=True, text=True, timeout=5, env=env)
        if state.returncode:
            provenance.update(status='partial', reason='status_unavailable', exit_code=state.returncode)
        else:
            result['dirty'] = bool(state.stdout)
            provenance.update(status='observed', reason='root_metadata')
    except subprocess.TimeoutExpired:
        provenance['reason'] = 'query_timeout'
    except (OSError, subprocess.SubprocessError) as error:
        provenance['reason'] = 'query_unavailable'
        if isinstance(error, OSError):
            import errno
            provenance['errno'] = errno.errorcode.get(error.errno, 'UNKNOWN')
    return result


def audit(root: Path) -> dict:
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('project must be a directory')
    from .readonly_scan import scan
    files, scan_metadata = scan(root)
    findings = [{'code':'discovery_exclusion','path':row['source'],'status':'observed',
                 'operation':row['operation'],'reason':row['reason'],
                 **({'errno':row['errno']} if 'errno' in row else {})}
                for row in scan_metadata['findings']]
    instructions, commands, services, tools = [], [], [], []
    for rel, raw in files.items():
        path = Path(rel)
        text = raw.decode('utf-8', errors='replace')
        if path.name in _INSTRUCTIONS:
            instructions.append({'path': rel, 'scope': path.parent.as_posix(),
                                 'status': 'observed', 'loading': 'harness_loading_unverified'})
            if re.search(r'\b(merge|deploy|approval|review|ownership|permission)\b', text, re.I):
                findings.append({'code': 'policy_review_required', 'path': rel,
                                 'status': 'needs-human-input',
                                 'detail': 'Preserve policy; review scope and contradictions before adoption.'})
        if path.name in {'package.json', 'composer.json'}:
            scripts = _json(raw).get('scripts', {})
            if isinstance(scripts, dict):
                for name in sorted(scripts):
                    if _safe_name(name):
                        commands.append({'command': ('npm run ' if path.name == 'package.json' else 'composer run-script ') + name,
                                         'cwd': path.parent.as_posix(), 'source': rel, 'status': 'observed_unverified'})
        if path.name == 'Makefile':
            for name in re.findall(r'^([A-Za-z0-9_.-]+):(?:[^=]|$)', text, re.M):
                if not name.startswith('.'):
                    commands.append({'command': 'make ' + name, 'cwd': path.parent.as_posix(),
                                     'source': rel, 'status': 'observed_unverified'})
        if path.name == 'pyproject.toml':
            section = re.search(r'^\[project\.scripts\]\s*$(.*?)(?=^\[|\Z)', text, re.M | re.S)
            if section:
                for name in re.findall(r'^([A-Za-z0-9_.-]+)\s*=', section.group(1), re.M):
                    commands.append({'command': name, 'cwd': path.parent.as_posix(),
                                     'source': rel, 'status': 'observed_unverified'})
        if path.name in {'config.toml', '.mcp.toml'}:
            for name in re.findall(r'^\[mcp_servers\.([A-Za-z0-9_.-]+)\]\s*$', text, re.M):
                tools.append({'name': name, 'source': rel, 'availability': 'declared_only',
                              'required': 'unknown', 'purpose': 'requires project review',
                              'fallback': 'unverified', 'setup_reference': rel})
        if path.name in {'compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml'}:
            # Deliberately bounded YAML recognition; never expose environment values.
            in_services = False
            for line in text.splitlines():
                if re.match(r'^services:\s*$', line):
                    in_services = True
                elif in_services and line and not line[0].isspace() and not line.startswith('#'):
                    in_services = False
                elif in_services:
                    match = re.match(r'^  ([A-Za-z0-9_.-]+):\s*$', line)
                    if match:
                        services.append({'name': match.group(1), 'source': rel, 'status': 'declared_unverified'})
        if path.name in {'.mcp.json', 'mcp.json', 'settings.json'}:
            config = _json(raw)
            servers = config.get('mcpServers', config.get('servers', {}))
            if isinstance(servers, dict):
                for name in sorted(servers):
                    if _safe_name(name):
                        tools.append({'name': name, 'source': rel, 'availability': 'declared_only',
                                      'required': 'unknown', 'purpose': 'requires project review',
                                      'fallback': 'unverified', 'setup_reference': rel})
    if not instructions:
        findings.append({'code': 'missing_instructions', 'status': 'observed'})
    for instruction in instructions:
        text = files[instruction['path']].decode('utf-8', errors='replace')
        scope = Path(instruction['path']).parent
        for name in re.findall(r'\bnpm run ([A-Za-z0-9_:@./-]+)', text):
            candidates = [c for c in commands if c['command'] == 'npm run ' + name
                          and (Path(c['cwd']) == scope or Path(c['cwd']) == Path('.'))]
            if not candidates:
                findings.append({'code': 'unknown_script_reference', 'path': instruction['path'],
                                 'status': 'inferred', 'detail': 'Referenced npm script absent from discovered manifests.'})
    documentation = '\n'.join(raw.decode('utf-8', errors='replace') for rel, raw in files.items()
                              if Path(rel).suffix.lower() in {'.md', '.rst'})
    for collection, code in ((services, 'missing_service_documentation'), (tools, 'missing_tool_documentation')):
        for item in collection:
            if not re.search(r'(?<![A-Za-z0-9_])' + re.escape(item['name']) + r'(?![A-Za-z0-9_])', documentation):
                findings.append({'code': code, 'source': item['source'], 'name': item['name'],
                                 'status': 'inferred', 'detail': 'Declared dependency has no matching documentation reference; purpose and fallback need review.'})
    dependencies = {rel: hashlib.sha256(raw).hexdigest() for rel, raw in files.items()}
    digest = hashlib.sha256(json.dumps(dependencies, sort_keys=True).encode()).hexdigest()
    from .stack import discover, configuration_resources
    stack = discover(root, files, scan_metadata=scan_metadata)
    repository = _git_provenance(root, scan_metadata)
    if repository['provenance']['status'] != 'observed':
        findings.append({'code':'git_provenance_unavailable', 'source':'.git', 'status':'observed',
                         'detail':repository['provenance']['reason']})
    return {'schema_version': 1, 'readiness': 'unverified', 'snapshot_digest': digest,
            'discovery_scan': scan_metadata,
            'stack': stack, 'environment_names': stack['environment_names'],
            'environment_evidence': stack['environment_evidence'], 'resources': configuration_resources(stack),
            'repository': repository,
            'instructions': instructions, 'commands': commands, 'services': services, 'tools': tools,
            'findings': findings, 'dependencies': dependencies,
            'limitations': ['Static discovery does not execute commands or verify service/tool access.',
                            'Harness instruction loading requires a separate live probe.',
                            'Discovery excludes links, credential files, binary files and files over 1 MiB.']}


def _entry(path):
    links = {name: os.path.relpath('docs/initloop-' + name + '.md', str(Path(path).parent)).replace(os.sep, '/')
             for name in ('workflow', 'stack', 'runbook')}
    return ('\n<!-- Initloop project workflow -->\n'
            'Consult [project workflow](' + links['workflow'] + '), [stack reference](' + links['stack'] + ') and '
            '[development runbook](' + links['runbook'] + ') for setup evidence, commands and unresolved checks.\n'
            'Existing project and team policies remain authoritative.\n')


def _text(value):
    """Render a bounded data field, never a source excerpt or credential-bearing configuration."""
    from .core import redact
    return redact(str(value)).replace('`', "'").replace('\n', ' ').replace('|', '/')[:1000]


def _source(row):
    return '`' + _text(row.get('source', 'unknown')) + ':' + _text(row.get('line', '?')) + '`'


def _provenance(report):
    repository = report.get('repository', {})
    revision = repository.get('revision') or 'unknown (no readable Git HEAD)'
    scan = report.get('discovery_scan', {})
    lines = ['Source snapshot: `' + report['snapshot_digest'] + '` (included permitted inputs only).',
            'Source revision: `' + revision + '`; dirty working tree: ' + str(repository.get('dirty')) + '.',
            'Tested revision: not tested. Runtime evidence: none recorded by static discovery.',
            'Setup state: proposed, not adopted, not verified. Adoption alone does not establish verification.',
            'Discovery coverage: `' + _text(scan.get('status', 'unknown')) + '`; excluded entries: `' + _text(scan.get('excluded_count', 'unknown')) + '`. Skipped inputs do not establish their contents or runtime readiness.']
    for row in scan.get('findings', []):
        lines.append('- Excluded `' + _text(row['source']) + '`; operation `' + _text(row['operation']) +
                     '`; observed reason `' + _text(row['reason']) + '`' +
                     ('; error `' + _text(row['errno']) + '`' if row.get('errno') else '') + '.')
    return lines


def _repository_lines(stack):
    evidence = stack.get('repository_evidence', {})
    lines = ['## Referenced paths, CI and test expectations', '',
             'These are static pointers, not verified commands or business truth. Follow explicit source references even outside conventional layouts; inspect ambiguities before choosing.', '']
    for row in evidence.get('references', []):
        lines.append('- Path literal at ' + _source(row) + '; resolution `' + _text(row['resolution']) +
                     '`; candidates `' + _text(row['candidates']) + '`; cwd/role inferred, runtime unverified.')
    for row in evidence.get('tests', []):
        lines.append('- Test `' + _text(row['name']) + '` at ' + _source(row) + '; assertions `' +
                     _text([r['kind'] for r in row['assertions']]) + '`; mock references `' + _text(len(row['mocks'])) +
                     '`; skip/expected-failure references `' + _text(len(row['skips'])) +
                     '`; collection/execution unknown; class/module/dynamic markers may be omitted. Read inputs, outputs, fixtures and consumers; reconcile stale expectations.')
    for row in evidence.get('fixtures', []):
        lines.append('- Fixture declaration `' + _text(row['name']) + '` at ' + _source(row) + '; data/setup relationships unverified.')
    for workflow in evidence.get('ci_workflows', []):
        for row in workflow['observations']:
            fields = {key: value for key, value in row.items() if key not in {'source', 'line', 'state', 'runtime_verified'}}
            lines.append('- CI declaration at ' + _source(row) + ': `' + _text(fields) + '`; not executed or authorized by discovery.')
    for row in evidence.get('unknowns', []):
        lines.append('- Unknown at ' + _source(row) + ': ' + _text(row['detail']))
    lines.extend(['', 'Missing/stale/dynamic references stay uncertain while independent work proceeds. Only meaningful unresolved intent/conflicts require a precise question citing the competing evidence; preserve the answer as user-confirmed evidence. Mocked/skipped tests do not establish real-provider fidelity. CI presence never authorizes deployment, secret access or tool installation.', ''])
    return lines


def _stack_document(report):
    stack = report.get('stack', {})
    lines = ['# Project stack reference', '',
             'Status: unverified static proposal. Inspect the cited files before choosing a runner.', '', *_provenance(report), '',
             'Versions below distinguish declared constraints from resolved lockfile versions. A version in an image tag is a declaration, not a running-server observation.',
             'All runtime-observed versions are unknown until an actual process/service probe is recorded.', '']
    for key, title in [('runtimes', 'Languages and runtimes'), ('frameworks', 'Frameworks'), ('app_servers', 'Application servers'),
                       ('databases', 'Databases'), ('caches', 'Caches'), ('queues', 'Queues'), ('workers', 'Workers'), ('apis', 'External APIs')]:
        lines.extend(['## ' + title, ''])
        rows = stack.get(key, [])
        for row in rows:
            lines.append('- `' + _text(row.get('name', 'unknown')) + '`; ' + _text(row.get('version_kind', 'declared')) + ' version: `' +
                         _text(row.get('version') or 'unknown') + '`; runtime-observed: unknown; source ' + _source(row) +
                         (('; ' + _text(row['detail'])) if row.get('detail') else '') + '.')
        if not rows:
            lines.append('- No supported static evidence found; investigate consumers/configuration. This is not proof of absence or inaccessibility.')
        lines.append('')
    lines.extend(['## Source configuration names', ''])
    for row in stack.get('environment_evidence', []):
        lines.append('- `' + _text(row['name']) + '` at ' + _source(row) + '; name only; value and runtime availability unverified.')
    if not stack.get('environment_evidence'):
        lines.append('- No supported literal environment-name evidence found; dynamic reads and unsupported source remain unknown.')
    lines.extend(['', '## API contract operations', ''])
    for contract in stack.get('contracts', []):
        lines.append('- `' + _text(contract['name']) + '` version `' + _text(contract.get('version') or 'unknown') +
                     '` at ' + _source(contract) + '; parse status `' + _text(contract['status']) + '`; runtime unverified.')
        for operation in contract['operations']:
            lines.append('  - `' + _text(operation['method']) + ' ' + _text(operation['path']) + '` at ' + _source(operation) + '; declared, not probed.')
        for detail in contract.get('limitations', []):
            lines.append('  - Limit: ' + _text(detail))
    if not stack.get('contracts'):
        lines.append('- No supported contract evidence found; inspect contract files and consumers directly.')
    lines.extend(['', '## Existing runner evidence and choice', ''])
    decision = stack.get('runner_decision', {})
    lines.append('Decision: `' + _text(decision.get('status', 'unknown')) + '`; ' + _text(decision.get('reason', 'Runner suitability remains unknown.')))
    if decision.get('preferred'):
        lines.append('Existing convention sources to inspect first: `' + _text(decision['preferred']) + '`. Preserve them when they work.')
    for runner in stack.get('runners', []):
        lines.append('- `' + _text(runner.get('kind', 'unknown')) + '` at ' + _source(runner) +
                     ('; command candidate `' + _text(runner['command']) + '`' if runner.get('command') else '') + '; declared, unverified.')
    for option in decision.get('options', []):
        lines.append('- Option `' + _text(option.get('kind', 'unknown')) + '`; ' + _text(option.get('rationale', '')) +
                     '; tradeoffs: ' + _text(option.get('tradeoffs', 'unknown')) + '.')
    lines.extend(['', 'Preserve existing working runner conventions. Missing local execution evidence is not evidence that an external dependency is inaccessible. Native execution is not sandboxed; inspect scripts and use actual harness permissions.', '',
                  '## Services, images, ports and storage', ''])
    for service in stack.get('services', []):
        lines.append('- `' + _text(service.get('name', 'unknown')) + '` at ' + _source(service) +
                     '; image declaration `' + _text(service.get('image') or 'unknown') + '`; ports `' + _text(service.get('ports', [])) +
                     '`; storage `' + _text(service.get('storage', [])) + '`; depends on `' + _text(service.get('depends_on', [])) + '`; runtime access unknown.')
    if not stack.get('services'):
        lines.append('- No supported service-runner definitions found. Do not invent a container prerequisite; inspect native services and external connection consumers.')
    lines.extend(['', '## Dependency relationships', ''])
    for rel in stack.get('relationships', []):
        lines.append('- `' + _text(rel.get('from', '?')) + '` → `' + _text(rel.get('to', '?')) + '` (' + _text(rel.get('kind', 'inferred')) + '); source ' + _source(rel) + '.')
    if not stack.get('relationships'):
        lines.append('- Not established by static evidence; trace the useful workflow through consumers.')
    lines.extend(['', *_repository_lines(stack), '## Conflicts and unknowns', ''])
    for conflict in stack.get('conflicts', []):
        lines.append('- Conflict: `' + _text(conflict.get('name', '?')) + '`; ' + _text(conflict.get('versions', [])) +
                     '; sources ' + _text(conflict.get('sources', [])) + '; ' + _text(conflict.get('detail', 'Review constraints before choosing a version.')))
    for unknown in stack.get('unknowns', []):
        lines.append('- ' + _text(unknown))
    lines.extend(['- Real external-service access and local-substitute fidelity are unverified. No unknown schema, production data or private business semantics are recovered by this report.', '',
                  '## Evidence maintenance', '',
                  'See [development runbook](initloop-runbook.md) and [project workflow](initloop-workflow.md). Record actual resolved/runtime versions, commands, source state and acceptance results after execution; keep failures and explicit unknowns.',
                  'Keep credentials out of this reference. Refresh detects file drift; it cannot certify semantic completeness or runtime correctness.', ''])
    return '\n'.join(lines)


def _command_candidates(report):
    candidates = list(report['commands'])
    for runner in report.get('stack', {}).get('runners', []):
        if runner.get('command'):
            candidates.append({'command': runner['command'], 'cwd': runner.get('scope', '.'), 'source': runner.get('source', '?')})
        if runner.get('kind') == 'compose':
            prefix = 'docker compose -f ' + shlex.quote(runner['source'])
            for action in ('up -d', 'stop', 'logs --tail 100'):
                candidates.append({'command': prefix + ' ' + action, 'cwd': '.', 'source': runner['source']})
    seen = set()
    return [row for row in candidates if not ((row['command'], row.get('cwd', '.')) in seen or seen.add((row['command'], row.get('cwd', '.'))))]


def _runbook_document(report):
    lines = ['# Development runbook proposal', '',
             'Status: unverified. These are repository-evidenced candidates, not a runnable setup certification.', '', *_provenance(report), '',
             'Read [stack reference](initloop-stack.md) for version declarations, existing runners, dependencies and unresolved conflicts. Prefer the established working runner; when none is established, choose an appropriate native/Compose/other supported option after comparing tradeoffs.', '',
             '## Prerequisites and setup', '',
             'Resolve runtime and dependency versions from cited manifests/lockfiles. Inspect install/setup scripts before invoking them. Use an isolated project environment; native execution is not sandboxed. Actual harness permissions and project policy remain authoritative.',
             'Connection details are deliberately absent here. Keep local credentials in an ignored project-local configuration file; never recover them from unrelated services or copy secrets into documentation.', '',
             '## Command candidates', '',
             'The following commands are declarations or direct runner candidates. None has been executed by this helper. Match each command to the intended action by reading its source; a name such as reset is not ownership proof.', '']
    commands = _command_candidates(report)
    for row in commands:
        lines.append('- `' + _text(row['command']) + '`; cwd `' + _text(row.get('cwd', '.')) + '`; source `' + _text(row.get('source', '?')) + '`; not tested.')
    if not commands:
        lines.append('- No supported command evidence discovered. Inspect source entrypoints and dependency installation before proposing setup/start commands.')
    lines.extend(['', '## Persistent development lifecycle', '',
                  '- Setup/build/install: select only commands supported by the repository and the chosen runner; record exact successful command, working directory and prerequisites.',
                  '- Start: identify the app and each required worker/dependency. Before launch, record which resources already exist and which exact new PID/service/container/network/volume names this session will own. Avoid occupied ports. Do not replace or stop unrelated resources.',
                  '- Running state: check useful requests/data and actual worker/dependency behavior. A live process or health200 does not prove readiness. Keep the app running when requested; publish its local URL plus exact stop/log commands and ownership identifiers.',
                  '- Stop: document the actual launch mode. For foreground runs record Ctrl-C plus exact ownership; for background runs record the PID/service identity at launch, the exact owned stop/wait command and listener-closure proof on the actual configured host/port that was reachable before stop. Require both owned process termination and that same listener closed; unused ports or arbitrary HTTP/network errors are not success. Separate cd from direct background launch; an AND-list job PID can be a shell, and job specifications depend on that shell\'s job table and job-control semantics; do not assume their availability or signal scope. Use a known direct child or the established named lifecycle for multiprocess services. Use the recorded owned process/service identity and preserve its data. Do not guess by process name, kill arbitrary listeners, prune Docker globally, or run project-wide teardown against pre-existing shared resources.',
                  '- Logs/debug: use observed project log commands or owned resource logs, redact credentials and inspect failures. Record log locations with access limits.',
                  '- Restart: stop/start only owned application resources and independently assert intended records survive, using IDs returned by create responses rather than hardcoded IDs. Disposable baseline/verification runs do not establish persistent development behavior.',
                  '- Optional controller support: `python3 <installed-skill>/scripts/initloop.py dev start/status/logs/stop/reset` can track a native foreground process through an external ledger; see the skill controller reference. It is not a sandbox or Compose manager. Only wire its owned data directory into an app when supported by the app configuration.',
                  '- Setup acceptance: compare row counts and seed identity before/after repeated setup in the same database, including extra user-created records. Do not hardcode a total row count or record ID from an example.',
                  '- Reset/seed: untested reset remains unverified, never a confirmed capability. No destructive reset is authorized by this proposal. Before an explicit reset, verify exact local ownership and data scope, preserve unrelated resources and state which synthetic records are expected afterward. A project name or environment label alone is insufficient.',
                  '', '## Workflow, errors and a small change', '',
                  'Freeze a useful input/output assertion from source/tests or the user objective. Verify persisted business results, setup reruns, representative dependency/auth/timeout errors and a reversible edit/test/reload or rebuild. Retain expected failures and passing evidence; do not weaken existing tests.',
                  'Document any runnable local substitute with its interface, deterministic scenarios, inferred schema and fidelity limits. A missing source/credential and a proven inaccessible external service are different findings; no private production equivalence is implied.', '',
                  '## Verification record to complete after execution', '',
                  '- Adopted setup: not recorded; proposed commands above remain unverified.',
                  '- Tested revision and working-tree changes: not tested; record exact state alongside actual command results.',
                  '- Runtime-observed versions: unknown; retain declared/resolved/runtime-observed distinctions.',
                  '- Start/stop/logs/reset and restart/data-preservation checks: not tested.',
                  '- Useful workflow, errors, change/test cycle, substitute fidelity and harness instruction loading: not tested.',
                  '', '## Refresh', '',
                  'Run `python3 <installed-skill>/scripts/initloop.py refresh PROJECT --manifest MANIFEST` using the external original workflow-manifest.json. Changed/added/removed inputs make prior evidence stale; rerun affected workflows and accurately update this runbook and stack reference.',
                  'Do not overwrite original provenance or relabel static regeneration verified. Unchanged inputs also remain unverified until runtime checks are recorded.', ''])
    return '\n'.join(lines)


def _document(report):
    lines = ['# Project workflow proposal', '',
             'Status: unverified. Review this proposal before adopting it. Static observations do not prove commands work.',
             '', 'Source snapshot: `' + report['snapshot_digest'] + '`.', '',
             '## Project map and command candidates', '',
             'See [stack reference](initloop-stack.md) and [development runbook](initloop-runbook.md). Commands are repository declarations; inspect them and follow actual harness permissions and project policy.']
    for command in report['commands']:
        lines.append('- `' + command['command'] + '` from `' + command['cwd'] + '`; source `' + command['source'] + '`; unverified.')
    if not report['commands']:
        lines.append('- No supported manifest commands discovered. Setup/start/stop/reset/test/build require investigation.')
    lines.extend(['', '## Services and tools', ''])
    for service in report['services']:
        lines.append('- Service `' + service['name'] + '` declared in `' + service['source'] + '`; availability unverified.')
    for tool in report['tools']:
        lines.append('- MCP `' + tool['name'] + '` declared in `' + tool['source'] + '`; connection, purpose, required workflows and fallback unverified. Do not copy credentials.')
    lines.extend(['', '## Development workflow', '',
                  'Inspect relevant scoped instructions, plan proportionately, reproduce the problem, make a focused change, validate it, review and report evidence.',
                  'Preserve existing delivery and permission policies. Resolve policy conflicts with the team; this document grants no new permissions.',
                  '', '## Unresolved verification', '',
                  'Verify install/start/stop/reset/test/build commands, synthetic data and local replacement fidelity, logs/debugging, and a small change/test cycle.',
                  'No runtime, authentication, MCP connection, service fidelity, or harness instruction-loading behavior has been tested by this static helper.',
                  '', '## Refresh', '',
                  'Run `python3 <installed-skill>/scripts/initloop.py refresh PROJECT --manifest MANIFEST` against the retained workflow-manifest.json. Changed or new inputs make evidence stale. Unchanged inputs remain unverified until independent runtime evidence is recorded.',
                  'Static discovery cannot establish completeness or semantic correctness. Regenerating this document is not revalidation.', ''])
    return '\n'.join(lines)


def propose(root: Path, destination: Path, mode: str = 'preserve', selected=None) -> dict:
    root = Path(root).resolve(strict=True)
    destination = Path(destination).resolve()
    if mode not in {'preserve', 'reconcile', 'replace'}:
        raise ValueError('mode must be preserve, reconcile or replace')
    if destination == root or root in destination.parents or destination in root.parents:
        raise ValueError('proposal destination must be outside source and its ancestors')
    if destination.exists():
        raise ValueError('proposal destination must not already exist')
    report = audit(root)
    existing = {i['path'] for i in report['instructions']}
    chosen = list(selected or [])
    if mode == 'replace':
        if not chosen or any(p not in existing for p in chosen):
            raise ValueError('replace requires explicitly selected existing project instruction files')
        if any(f.get('path') in chosen and f['code']=='policy_review_required' for f in report['findings']):
            raise ValueError('selected files contain team policy; reconcile or resolve policy preservation before replacement')
    elif chosen:
        raise ValueError('selected files apply only to replace mode')
    if mode != 'preserve':
        for name in ('workflow', 'stack', 'runbook'):
            rel = 'docs/initloop-' + name + '.md'
            if (root / rel).exists() or (root / rel).is_symlink():
                raise ValueError(rel + ' already exists; reconcile shared documentation manually')
    if mode != 'preserve':
        from .core import secret_like
        if any(secret_like((root / rel).read_text()) for rel in existing):
            raise ValueError('project instructions contain recognizable credential material; remove secrets before generating copied instructions')
    # All checks precede creating output. Never open source paths for writing.
    destination.mkdir(parents=True)
    report_path = destination / 'workflow-audit.json'
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    manifest_path = destination / 'workflow-manifest.json'
    manifest = {'schema_version': 1, 'snapshot_digest': report['snapshot_digest'],
                'discovery_scan': report['discovery_scan'],
                'dependencies': report['dependencies'], 'verification': 'unverified',
                'discovery': 'static', 'mode': mode, 'repository': report['repository']}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    affected = []
    if mode != 'preserve':
        paths = chosen if mode == 'replace' else sorted(existing | _INSTRUCTIONS)
        for name, content in [('workflow', _document(report)), ('stack', _stack_document(report)), ('runbook', _runbook_document(report))]:
            rel = 'docs/initloop-' + name + '.md'
            doc = destination / 'files' / rel
            doc.parent.mkdir(parents=True, exist_ok=True)
            doc.write_text(content)
            affected.append(rel)
        for rel in paths:
            candidate = destination / 'files' / rel
            candidate.parent.mkdir(parents=True, exist_ok=True)
            original = (root / rel).read_text() if rel in existing else ''
            if mode == 'replace':
                backup = destination / 'originals' / rel
                backup.parent.mkdir(parents=True, exist_ok=True)
                backup.write_text(original)
            candidate.write_text((original if mode == 'reconcile' else '') + _entry(rel))
            affected.append(rel)
    return {'mode': mode, 'applied': False, 'affected_files': affected,
            'report_path': str(report_path), 'manifest_path': str(manifest_path),
            'readiness': 'unverified', 'policy_decisions': [f for f in report['findings'] if f['code'] == 'policy_review_required']}


def refresh(root: Path, manifest: Path) -> dict:
    """Compare provenance without modifying it or claiming runtime revalidation."""
    frozen = json.loads(Path(manifest).read_text())
    if not isinstance(frozen,dict) or frozen.get('schema_version') != 1 or not isinstance(frozen.get('dependencies'), dict):
        raise ValueError('invalid workflow provenance manifest')
    before = frozen['dependencies']
    current = audit(root)
    after = current['dependencies']
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(p for p in set(before) & set(after) if before[p] != after[p])
    return {'status': 'stale' if added or removed or changed else 'unverified',
            'inputs_unchanged': not (added or removed or changed), 'added': added,
            'removed': removed, 'changed': changed, 'revalidation_required': True,
            'snapshot_digest': current['snapshot_digest'], 'discovery_scan': current['discovery_scan'],
            'discovery_scan_changed': (frozen['discovery_scan'] != current['discovery_scan']
                                       if 'discovery_scan' in frozen else None),
            'detail': 'Only included permitted inputs were compared. Partial/excluded discovery remains explicit; input equality is not verification. Re-run affected workflow and harness checks.'}
