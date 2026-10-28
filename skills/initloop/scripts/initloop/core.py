"""Deterministic inventory/snapshot/evidence controller; execution lives in explicit backends."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from .git_context import project_environment


class PolicyError(ValueError):
    pass


def _credential_key(name):
    return bool(re.search(r'key|token|secret|password|passwd|credential', name, re.I))


class _RedactionLimit(ValueError):
    pass


def _redact_json_value(value, depth, structure_depth=0):
    if structure_depth >= 64:
        raise _RedactionLimit('structured output nesting limit')
    if isinstance(value, dict):
        return {key: '[REDACTED]' if _credential_key(key) else
                _redact_json_value(item, depth, structure_depth + 1)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_json_value(item, depth, structure_depth + 1) for item in value]
    if isinstance(value, str):
        if depth >= 8:
            # Encoded output beyond the inspected budget is omitted rather than
            # returned unchecked with a possible credential still inside it.
            return '[REDACTED: encoded output nesting limit]'
        return _redact_json_fragments(value, depth + 1)
    return value


def _redact_json_fragments(text, depth=0):
    """Handle JSON logs, prefixed JSON, and JSON serialized inside string fields."""
    decoder = json.JSONDecoder()
    output = []
    position = 0
    while position < len(text):
        if text[position] not in '{["':
            output.append(text[position])
            position += 1
            continue
        try:
            value, length = decoder.raw_decode(text[position:])
            sanitized = _redact_json_value(value, depth)
            rendered = (text[position:position + length] if sanitized == value else
                        json.dumps(sanitized, ensure_ascii=False))
        except (_RedactionLimit, RecursionError):
            # Decoder, traversal, comparison or encoder limits must never turn
            # log collection into an exception or echo the uninspected suffix.
            return ''.join(output) + '[REDACTED: structured output nesting limit]'
        except ValueError:
            output.append(text[position])
            position += 1
            continue
        output.append(rendered)
        position += length
    return ''.join(output)


def redact(text):
    text = _redact_json_fragments(str(text))
    # Best effort for incomplete/non-JSON log fragments with quoted field names.
    def quoted_field(match):
        try:
            key = json.loads(match.group(1))
        except ValueError:
            return match.group(0)
        return match.group(1) + ': "[REDACTED]"' if _credential_key(key) else match.group(0)
    text = re.sub(r'("(?:\\.|[^"\\])*")\s*:\s*("(?:\\.|[^"\\])*"|[-+0-9.eE]+|true|false|null)', quoted_field, text)
    text = re.sub(r'https?://[^\s<>"\x27]+', '[URL redacted]', text)
    text = re.sub(r'''(?i)\b(bearer\s+)[^\s"'\\,;}]+''', r'\1[REDACTED]', text)
    text = re.sub(r'\b(?:sk-[\w-]{8,}|AIza[\w-]+|gh[pousr]_[\w]+)\b', '[REDACTED]', text)
    return re.sub(r'(?im)(\b[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z_]*\s*[=:]\s*)[^\s,;]+', r'\1[REDACTED]', text)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def _placeholder(value):
    lower = value.lower()
    return (not value or value.startswith(('$', '<')) or
            lower in {'none', 'null', 'undefined', 'false', 'true', 'changeme'} or
            bool(re.match(r'^(?:example|synthetic|initloop|local|placeholder)(?:$|[-_:./])', lower)))


def _computed_value(value, declaration=False):
    # A lexical expression boundary, shared by languages rather than per-language
    # exemptions. Bare configuration scalars remain screened. This is not a parser
    # or proof that arbitrary source contains no credentials.
    identifier = r'[A-Za-z_$][A-Za-z0-9_$]*'
    member = identifier + r'(?:(?:\.|::|\?\.)' + identifier + r')*'
    return bool(re.match(member + r'\s*[([]', value) or
                (declaration and re.fullmatch(
                    identifier + r'(?:(?:\.|::|\?\.)' + identifier + r')+\s*;?\s*', value)))


def secret_like(text):
    """Screen literal assignments and recognizable tokens, not computed auth code.

    Empty/null/boolean defaults and explicit synthetic placeholders are permitted.
    Unquoted scalar configuration values remain conservative; this heuristic is
    not a language parser and cannot establish that arbitrary source is secret-free.
    """
    if re.search(r'\b(?:sk-[\w-]{8,}|AIza[\w-]+|gh[pousr]_[\w]+)\b|https?://[^\s/]+:[^\s/]+@', text):
        return True
    for token in re.findall(r'(?i:bearer)\s+([A-Za-z0-9._-]{8,})', text):
        if not re.fullmatch(r'(?:synthetic|example|placeholder)-[A-Za-z0-9._-]+', token):
            return True
    assignment = r"""(?im)\b[A-Z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z_]*["']?\s*[=:]\s*"""
    for match in re.finditer(assignment, text):
        value = text[match.end():].split('\n', 1)[0].strip()
        if not value:
            continue
        if value[0] in {'"', "'"}:
            literal = re.match(r"""(["'])((?:\\.|(?!\1).)*)\1""", value)
            literal_value = literal.group(2) if literal else value[1:]
            if value.startswith(value[0] * 3):
                literal_value = value[3:].split(value[0] * 3, 1)[0]
            if not _placeholder(literal_value):
                return True
            continue
        # A dotted scalar in an environment/config assignment can be a literal
        # token. Member access alone is treated as source only when this same
        # assignment has explicit variable-declaration syntax; no token-shape
        # exemption (JWT or otherwise) is used. Calls/subscripts are expressions.
        line_start = text.rfind('\n', 0, match.start()) + 1
        prefix = text[line_start:match.start()]
        declaration = bool(re.search(r'(?:^|[;{}])\s*(?:export\s+)?(?:const|let|var)\s+$', prefix))
        if _computed_value(value, declaration):
            continue
        scalar = re.split(r'[\s,;)}\]]', value, maxsplit=1)[0]
        if not _placeholder(scalar):
            return True
    return False


def write_json(path, data):
    path = Path(path)
    # Unique exclusive temporary file prevents link-following/truncation attacks.
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream,indent=2,sort_keys=True);stream.write('\n')
        os.replace(tmp,path)
    finally:
        tmp.unlink(missing_ok=True)


def safe_path(root, name):
    root = Path(root).resolve()
    p = PurePosixPath(name)
    if not name or p.is_absolute() or '..' in p.parts or '\\' in name or '\x00' in name:
        raise PolicyError('unsafe relative path')
    target = Path(root) / p
    if any(parent.is_symlink() for parent in [target, *list(target.parents)[:len(p.parts)-1]]):
        raise PolicyError('symlinks are not permitted')
    if not target.resolve().is_relative_to(Path(root).resolve()):
        raise PolicyError('path escapes root')
    return target


def excluded(name):
    p = PurePosixPath(name)
    return (any(x in {'.git','.ssh','.aws','.codex','.claude','node_modules','vendor','.venv','__pycache__','storage','logs'} for x in p.parts)
            or any(x.startswith('.env') and x not in {'.env.example','.env.sample','.env.template'} for x in p.parts)
            or p.suffix.lower() in {'.pem','.key','.p12','.sqlite','.sqlite3','.db','.log'}
            or p.name in {'auth.json','credentials.json','.npmrc','.pypirc','.netrc'})


def tracked(root):
    result = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'ls-files','-z','--cached'], capture_output=True, check=True, env=project_environment())
    return sorted(set(x for x in result.stdout.decode().split('\0') if x))


def tree_digest(root):
    entries = []
    for p in sorted(Path(root).rglob('*')):
        if p.is_symlink():
            raise PolicyError('symlink in snapshot')
        if p.is_file():
            entries.append((p.relative_to(root).as_posix(), digest(p.read_bytes()), p.stat().st_mode & 0o111))
    return digest(json.dumps(entries).encode())


def runtime_modes(root):
    """Runtime bind roots are readable by the container UID; controller parents remain private."""
    root=Path(root); root.chmod(0o755)
    for path in root.rglob('*'):
        if path.is_symlink():
            raise PolicyError('symlink in runtime input')
        path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)


def _snapshot_receipt(root):
    root=Path(root).resolve()
    return root.with_name(root.name+'.initloop-snapshot.json')


def _register_snapshot(root):
    write_json(_snapshot_receipt(root),{'schema':1,'purpose':'initloop-runtime-input','digest':tree_digest(root)})
    _snapshot_receipt(root).chmod(0o400)


def validate_runtime_input(root):
    original=Path(root)
    if original.is_symlink(): raise PolicyError('runtime snapshot cannot be a symlink')
    root=original.resolve()
    home=Path.home().resolve()
    if root==home or root in home.parents:
        raise PolicyError('home directories and filesystem ancestors cannot be runtime inputs')
    receipt=_snapshot_receipt(root)
    if not receipt.is_file() or receipt.is_symlink() or receipt.stat().st_size>4096:
        raise PolicyError('execute requires a controller-created snapshot from begin/repair')
    record=json.loads(receipt.read_text())
    if not isinstance(record,dict) or record.get('purpose')!='initloop-runtime-input' or record.get('digest')!=tree_digest(root):
        raise PolicyError('runtime snapshot changed or ownership receipt is invalid')
    return root


def snapshot(root, destination, include_dirty=False):
    root, destination = Path(root).resolve(), Path(destination).absolute()
    if destination.resolve().is_relative_to(root) or root.is_relative_to(destination.resolve()):
        raise PolicyError('snapshot and source must be disjoint')
    if destination.exists():
        raise PolicyError('snapshot destination already exists')
    try:
        names = tracked(root)
        dirty = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'diff','--no-ext-diff','--no-textconv','--name-only'],capture_output=True,check=True,env=project_environment()).stdout
        staged = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'diff','--no-ext-diff','--no-textconv','--cached','--name-only'],capture_output=True,check=True,env=project_environment()).stdout
        revision_result = subprocess.run(['git','-C',str(root),'rev-parse','--verify','HEAD'],capture_output=True,env=project_environment())
        revision = revision_result.stdout.decode().strip() if revision_result.returncode == 0 else None
    except subprocess.CalledProcessError as exc:
        raise PolicyError('source must be a Git repository') from exc
    # An initial index has no HEAD: staged initial content is an explicit snapshot input.
    dirty_flag = bool(dirty or (staged and revision))
    if dirty_flag and not include_dirty:
        raise PolicyError('tracked changes require --include-dirty; untracked files are always excluded')
    omitted, accepted, total = [], [], 0
    for name in names:
        path = safe_path(root, name)
        if excluded(name):
            omitted.append(name)
            continue
        if not path.is_file():
            raise PolicyError('tracked path missing or unsupported: '+name)
        size = path.stat().st_size
        total += size
        if size > 4*1024*1024 or total > 128*1024*1024:
            raise PolicyError('snapshot size budget exceeded')
        raw=path.read_bytes()
        if b'\0' not in raw and secret_like(raw.decode(errors='replace')):
            raise PolicyError('recognizable credential material in tracked file: '+name)
        accepted.append(name)
    destination.mkdir(parents=True, mode=0o755)
    destination.chmod(0o755)
    for name in accepted:
        target = safe_path(destination, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root/name, target)
        target.chmod(0o755 if (root/name).stat().st_mode & 0o111 else 0o644)
    runtime_modes(destination)
    _register_snapshot(destination)
    return {'digest':tree_digest(destination),'revision':revision,'dirty':dirty_flag,'excluded':omitted,'files':accepted}


class Inventory:
    MANIFESTS = {'composer.json':'php','package.json':'javascript','pyproject.toml':'python','requirements.txt':'python','Cargo.toml':'rust','go.mod':'go','Gemfile':'ruby','pom.xml':'java','build.gradle':'jvm','CMakeLists.txt':'native','mix.exs':'elixir','pubspec.yaml':'dart'}

    def __init__(self, root):
        self.root = Path(root).resolve()

    def scan(self):
        from .readonly_scan import scan
        files, scan_metadata = scan(self.root)
        components, env, resources, commands = [], set(), [], []
        findings = [{'kind':'discovery-exclusion','evidence':row['source'],'state':'observed',
                     'operation':row['operation'],'reason':row['reason'],
                     **({'errno':row['errno']} if 'errno' in row else {})}
                    for row in scan_metadata['findings']]
        for name, raw in files.items():
            p = Path(name)
            if p.name in self.MANIFESTS:
                components.append({'path':str(p.parent), 'language':self.MANIFESTS[p.name], 'manifest':name})
                findings.append({'kind':'manifest','evidence':name,'state':'observed'})
                if p.name in {'package.json','composer.json'}:
                    try:
                        doc=json.loads(raw)
                        if not isinstance(doc,dict) or not isinstance(doc.get('scripts',{}),dict):
                            raise ValueError('invalid scripts manifest')
                        for key in doc.get('scripts',{}):
                            commands.append({'name':key,'cwd':str(p.parent),'source':name,'state':'inferred','verified':False})
                    except (ValueError,UnicodeError):
                        findings.append({'kind':'invalid-manifest','evidence':name,'state':'observed'})
            if p.name.startswith('.env.'):
                for line in raw.decode(errors='replace').splitlines():
                    match=re.match(r'\s*([A-Z][A-Z0-9_]*)\s*=',line)
                    if match:
                        key=match.group(1); env.add(key)
                        kind=next((k for k, pattern in [('database','DB|DATABASE'),('queue','QUEUE'),('cache','REDIS|CACHE'),('storage','S3|STORAGE|BUCKET'),('identity','OAUTH|AUTH|OIDC'),('mail','MAIL|SMTP'),('api','API|URL|ENDPOINT')] if re.search(pattern,key)),None)
                        if kind:
                            resources.append({'kind':kind,'configuration':key,'source':name,'state':'inferred','strategy':'needs contract inspection','workflows':[]})
            if p.name in {'artisan','Dockerfile','compose.yaml','compose.yml','docker-compose.yml','Makefile'} or any(x in p.parts for x in ('migrations','routes','seeders','factories')):
                findings.append({'kind':'workflow-evidence','evidence':name,'state':'observed'})
        from .stack import discover, configuration_resources
        stack = discover(self.root, files, scan_metadata=scan_metadata)
        return {'stack': stack, 'schema': 1, 'components': components, 'findings': findings,
                'discovery_scan': scan_metadata,
                'environment_names': sorted(env | set(stack['environment_names'])),
                'environment_evidence': stack['environment_evidence'],
                'resources': configuration_resources(stack), 'commands': commands,
                'limitations': ['Static discovery is incomplete; resource edges and commands require runtime verification.']}


class Run:
    TRANSITIONS={'created':{'baseline','blocked','cancelled'},'baseline':{'repaired','blocked','cancelled'},'repaired':{'repaired','verified','partial','blocked','cancelled'},'partial':{'repaired','blocked','cancelled'},'blocked':{'baseline','repaired','cancelled'},'verified':set(),'cancelled':set()}

    @classmethod
    def create(cls, source, runs_root, contract, include_dirty=False):
        if not isinstance(contract,dict) or not isinstance(contract.get('objective'),str) or not isinstance(contract.get('checks'),list):
            raise PolicyError('contract needs objective and checks')
        if len(contract['checks'])>12:
            raise PolicyError('acceptance budget is at most 12 checks')
        for check in contract['checks']:
            if not isinstance(check,dict) or not all(k in check for k in ('name','argv','source')) or not isinstance(check['argv'],list) or not check['argv'] or not all(isinstance(x,str) and '\x00' not in x for x in check['argv']):
                raise PolicyError('each check needs name, string argv and expectation source')
            if not all(isinstance(check[k],str) and check[k].strip() for k in ('name','source')):
                raise PolicyError('check name and expectation source must be nonempty strings')
            if type(check.get('timeout',60)) is not int or not 1<=check.get('timeout',60)<=300:
                raise PolicyError('check timeout must be 1..300 seconds')
            if type(check.get('exit_code',0)) is not int or not isinstance(check.get('contains',[]),list) or not all(isinstance(x,str) for x in check.get('contains',[])):
                raise PolicyError('check expectations need integer exit_code and string contains list')
        protected=contract.get('protected_paths',[])
        if not isinstance(protected,list) or not all(isinstance(x,str) for x in protected):
            raise PolicyError('protected_paths must be relative paths')
        for name in protected:
            safe_path(source,name)
        runs_root=Path(runs_root).resolve(); source=Path(source).resolve()
        if runs_root.is_relative_to(source) or source.is_relative_to(runs_root):
            raise PolicyError('controller state must be outside source')
        runs_root.mkdir(parents=True,exist_ok=True,mode=0o700)
        root=runs_root / uuid.uuid4().hex; root.mkdir(mode=0o700)
        snap=snapshot(source,root/'baseline',include_dirty)
        write_json(root/'contract.json',contract); (root/'contract.json').chmod(0o400)
        state={'schema':1,'id':root.name,'phase':'created','source':str(source),'snapshot':snap,'contract_digest':digest((root/'contract.json').read_bytes()),'created':time.time(),'events':[],'attempts':0,'max_attempts':3}
        write_json(root/'state.json',state)
        return cls(root)

    def __init__(self, root):
        self.root=Path(root).resolve(); self.contract_path=self.root/'contract.json'
        self.state=json.loads((self.root/'state.json').read_text())

    def check_contract(self):
        if digest(self.contract_path.read_bytes())!=self.state['contract_digest']:
            raise PolicyError('frozen acceptance contract changed')
        return json.loads(self.contract_path.read_text())

    def transition(self, phase, evidence=None):
        if phase not in self.TRANSITIONS[self.state['phase']]:
            raise PolicyError('invalid transition '+self.state['phase']+' -> '+phase)
        if phase=='verified' and not evidence:
            raise PolicyError('verification evidence required')
        self.state['phase']=phase
        self.state['events'].append({'phase':phase,'time':time.time(),'evidence':evidence})
        write_json(self.root/'state.json',self.state)

    def record_baseline(self, results):
        self.check_contract()
        if tree_digest(self.root/'baseline') != self.state['snapshot']['digest']:
            raise PolicyError('baseline snapshot changed after freeze')
        write_json(self.root/'baseline-results.json',results)
        self.transition('baseline','baseline-results.json')

    def check_baseline(self):
        if tree_digest(self.root / 'baseline') != self.state['snapshot']['digest']:
            raise PolicyError('baseline snapshot changed after freeze')

    def _repair_entries(self, files, contract):
        if not isinstance(files, dict) or not files or len(files) > 128:
            raise PolicyError('repair must be a nonempty path/content map of at most 128 files')
        entries = {}
        total = 0
        baseline = self.root / 'baseline'
        for name, entry in files.items():
            if not isinstance(name, str):
                raise PolicyError('repair paths must be strings')
            target = safe_path(baseline, name)
            canonical = PurePosixPath(name)
            if not canonical.parts or canonical in entries:
                raise PolicyError('empty or duplicate normalized repair path')
            if target.is_dir() or any((baseline / parent).is_file() for parent in canonical.parents):
                raise PolicyError('repair path collides with an existing file or directory')
            for protected in contract.get('protected_paths', []):
                if canonical == PurePosixPath(protected) or PurePosixPath(protected) in canonical.parents:
                    raise PolicyError('repair cannot change acceptance input')
            mode = None
            if isinstance(entry, dict):
                if 'content' not in entry or set(entry) - {'content', 'mode'}:
                    raise PolicyError('repair object needs content and optional safe mode')
                if 'mode' in entry:
                    if entry['mode'] not in ('0644', '0755'):
                        raise PolicyError('repair mode must be the string 0644 or 0755')
                    mode = int(entry['mode'], 8)
                content = entry['content']
            else:
                content = entry
            if excluded(name) or not isinstance(content, str) or '\x00' in content:
                raise PolicyError('repair needs nonexcluded UTF-8 text files')
            try:
                size = len(content.encode('utf-8'))
            except UnicodeEncodeError as exc:
                raise PolicyError('repair content must be valid UTF-8 text') from exc
            if size > 4 * 1024 * 1024:
                raise PolicyError('oversized repair file')
            if secret_like(content):
                raise PolicyError('repair includes recognizable credential material; use synthetic configuration')
            total += size
            if total > 16 * 1024 * 1024:
                raise PolicyError('repair size budget exceeded')
            entries[canonical] = (content, mode)
        if any(parent in entries for name in entries for parent in name.parents):
            raise PolicyError('repair paths contain a file/directory collision')
        return entries

    def _next_attempt(self):
        # A crash between publishing artifacts and committing state must neither
        # overwrite evidence nor restore an already consumed repair budget slot.
        latest = self.state['attempts']
        for path in self.root.iterdir():
            match = re.fullmatch(r'repair-([0-9]+)(?:\.diff|\.initloop-snapshot\.json)?', path.name)
            if match:
                latest = max(latest, int(match.group(1)))
        if latest >= self.state['max_attempts']:
            raise PolicyError('repair attempt budget exhausted')
        return latest + 1

    def _repair_diff(self, staging):
        # Git writes valid missing-newline markers, path quoting, additions and
        # executable mode headers. No external diff drivers or text converters.
        result = subprocess.run(
            ['git', '-c', 'core.quotePath=false', 'diff', '--no-index',
             '--no-ext-diff', '--no-textconv', '--no-renames', '--binary',
             '--src-prefix=', '--dst-prefix=', '--', 'a', 'b'],
            cwd=staging, capture_output=True)
        if result.returncode not in (0, 1):
            raise PolicyError('unable to generate repair diff')
        return result.stdout

    def patch(self, files):
        contract = self.check_contract()
        self.check_baseline()
        if self.state['phase'] not in {'baseline', 'partial', 'blocked', 'repaired'}:
            raise PolicyError('repair requires recorded baseline')
        entries = self._repair_entries(files, contract)
        attempt = self._next_attempt()
        name = 'repair-' + str(attempt)
        repair = self.root / name
        diff_path = self.root / (name + '.diff')
        receipt = _snapshot_receipt(repair)
        published = []
        try:
            with tempfile.TemporaryDirectory(prefix='.repair-build-', dir=self.root) as temporary:
                staging = Path(temporary)
                before, after = staging / 'a', staging / 'b'
                shutil.copytree(self.root / 'baseline', before)
                self.check_baseline()
                if tree_digest(before) != self.state['snapshot']['digest']:
                    raise PolicyError('baseline changed during repair construction')
                shutil.copytree(before, after)
                for relative, (content, mode) in entries.items():
                    target = safe_path(after, relative.as_posix())
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open('w', encoding='utf-8', newline='') as stream:
                        stream.write(content)
                    if mode is not None:
                        target.chmod(mode)
                runtime_modes(after)
                repair_digest = tree_digest(after)
                _register_snapshot(after)
                staged_diff = staging / 'repair.diff'
                staged_diff.write_bytes(self._repair_diff(staging))
                # Recheck immutable inputs after all reads and before publication.
                self.check_baseline()
                self.check_contract()
                next_state = dict(self.state, attempts=attempt, repair=str(repair),
                                  repair_digest=repair_digest, phase='repaired')
                next_state['events'] = self.state['events'] + [
                    {'phase': 'repaired', 'time': time.time(), 'evidence': diff_path.name}]
                staged_state = staging / 'state.json'
                write_json(staged_state, next_state)
                if any(path.exists() or path.is_symlink() for path in (repair, diff_path, receipt)):
                    raise PolicyError('repair artifact appeared during construction; retry safely')
                after.rename(repair)
                published.append(repair)
                # Hard links publish files exclusively: never replace prior evidence.
                os.link(staged_diff, diff_path)
                published.append(diff_path)
                os.link(_snapshot_receipt(after), receipt)
                published.append(receipt)
                os.replace(staged_state, self.root / 'state.json')
                self.state = next_state
        except Exception as exc:
            for path in reversed(published):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            # Keep a diagnostic without retaining a partially trusted runtime tree.
            # Do not echo exception text: it can contain paths or input contents.
            try:
                write_json(self.root / ('repair-failed-' + uuid.uuid4().hex + '.json'),
                           {'attempt': attempt, 'error_type': type(exc).__name__, 'time': time.time()})
            except OSError:
                pass
            raise
        return {'workspace': str(repair), 'digest': repair_digest, 'diff': str(diff_path)}

    def verify(self, backend, image=None):
        contract=self.check_contract()
        self.check_baseline()
        if self.state['phase']!='repaired':
            raise PolicyError('verification requires isolated repair')
        repair=Path(self.state['repair'])
        if tree_digest(repair)!=self.state['repair_digest']:
            raise PolicyError('repair changed after checkpoint')
        checks=contract['checks']; results=[]
        if not checks:
            self.transition('partial','no application assertions; setup unverified')
            return {'status':'partial','results':[]}
        if not image and getattr(backend,'requires_image',True):
            raise PolicyError('explicit local runtime image required')
        for repetition in range(2):
            for check in checks:
                result=backend.execute(repair,image,check['argv'],timeout=check.get('timeout',60))
                result.update(name=check['name'],repetition=repetition+1)
                result['passed']=result.get('outcome')=='completed' and result.get('cleanup','removed')=='removed' and result['exit_code']==check.get('exit_code',0) and all(x in result['stdout'] for x in check.get('contains',[]))
                results.append(result)
        self.check_contract()
        self.check_baseline()
        if tree_digest(repair)!=self.state['repair_digest']:
            raise PolicyError('source changed during verification')
        write_json(self.root/'verification.json',results)
        self.transition('verified' if all(r['passed'] for r in results) else 'partial','verification.json')
        return {'status':self.state['phase'],'results':results,'snapshot':self.state['repair_digest']}

    def report(self):
        self.check_contract()
        return {'run':self.state,'onboarding':self.state['phase'],'everyday_development':'unverified unless acceptance includes edit/test cycle','real_provider_fidelity':'unverified','limitations':['Harness filesystem access is not constrained by this helper. Controller state must remain inaccessible to untrusted agents.','Verification certifies only the frozen checks; supply independent assertions from known contracts.']}
