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


class PolicyError(ValueError):
    pass


def redact(text):
    text = re.sub(r'https?://[^\s<>"\x27]+', '[URL redacted]', str(text))
    text = re.sub(r'(?i)\b(bearer\s+)\S+', r'\1[REDACTED]', text)
    text = re.sub(r'\b(?:sk-[\w-]{8,}|AIza[\w-]+|gh[pousr]_[\w]+)\b', '[REDACTED]', text)
    return re.sub(r'(?im)(\b[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z_]*\s*[=:]\s*)[^\s,;]+', r'\1[REDACTED]', text)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def secret_like(text):
    """Reject recognizable credential material; redaction is a separate output policy."""
    if re.search(r'\b(?:sk-[\w-]{8,}|AIza[\w-]+|gh[pousr]_[\w]+)\b|https?://[^\s/]+:[^\s/]+@',text):
        return True
    for token in re.findall(r'(?i:bearer)\s+([A-Za-z0-9._-]{8,})',text):
        if not re.fullmatch(r'(?:synthetic|example|placeholder)-[A-Za-z0-9._-]+',token):
            return True
    # Quoted literal assignments remain screened; computed expressions are not literal credentials.
    for match in re.finditer(r'''(?i)\b[A-Z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z_]*["']?\s*[=:]\s*(["'])([^"']+)\1''',text):
        value=match.group(2)
        if not value.startswith(('$','<')) and not any(x in value.lower() for x in ('example','synthetic','initloop','local','changeme','placeholder')):
            return True
    # Preserve inline/YAML/environment screening; exempt only computed PHP function expressions.
    for match in re.finditer(r'(?im)\b[A-Z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD)[A-Z_]*\s*[=:]\s*[\x22\x27]?([^\s\x22\x27,;]+)',text):
        value=match.group(1)
        if match.start()>0 and text[match.start()-1]=='$' and re.match(r'[A-Za-z_][A-Za-z0-9_\\:]*\(',value):
            continue
        if value and not value.startswith(('$','<')) and not any(x in value.lower() for x in ('example','synthetic','initloop','local','changeme','placeholder')):
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
    result = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'ls-files','-z','--cached'], capture_output=True, check=True)
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
        dirty = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'diff','--no-ext-diff','--no-textconv','--name-only'],capture_output=True,check=True).stdout
        staged = subprocess.run(['git','-c','core.fsmonitor=false','-C',str(root),'diff','--no-ext-diff','--no-textconv','--cached','--name-only'],capture_output=True,check=True).stdout
        revision_result = subprocess.run(['git','-C',str(root),'rev-parse','--verify','HEAD'],capture_output=True)
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
        components, findings, env, resources, commands = [], [], set(), [], []
        for name in tracked(self.root):
            if excluded(name):
                continue
            p = safe_path(self.root, name)
            if not p.is_file() or p.stat().st_size > 1024*1024:
                continue
            if p.name in self.MANIFESTS:
                components.append({'path':str(p.parent.relative_to(self.root)), 'language':self.MANIFESTS[p.name], 'manifest':name})
                findings.append({'kind':'manifest','evidence':name,'state':'observed'})
                if p.name in {'package.json','composer.json'}:
                    try:
                        doc=json.loads(p.read_text())
                        if not isinstance(doc,dict) or not isinstance(doc.get('scripts',{}),dict):
                            raise ValueError('invalid scripts manifest')
                        for key in doc.get('scripts',{}):
                            commands.append({'name':key,'cwd':str(p.parent.relative_to(self.root)),'source':name,'state':'inferred','verified':False})
                    except (ValueError,UnicodeError):
                        findings.append({'kind':'invalid-manifest','evidence':name,'state':'observed'})
            if p.name.startswith('.env.'):
                for line in p.read_text(errors='replace').splitlines():
                    match=re.match(r'\s*([A-Z][A-Z0-9_]*)\s*=',line)
                    if match:
                        key=match.group(1); env.add(key)
                        kind=next((k for k, pattern in [('database','DB|DATABASE'),('queue','QUEUE'),('cache','REDIS|CACHE'),('storage','S3|STORAGE|BUCKET'),('identity','OAUTH|AUTH|OIDC'),('mail','MAIL|SMTP'),('api','API|URL|ENDPOINT')] if re.search(pattern,key)),None)
                        if kind:
                            resources.append({'kind':kind,'configuration':key,'source':name,'state':'inferred','strategy':'needs contract inspection','workflows':[]})
            if p.name in {'artisan','Dockerfile','compose.yaml','compose.yml','docker-compose.yml','Makefile'} or any(x in p.parts for x in ('migrations','routes','seeders','factories')):
                findings.append({'kind':'workflow-evidence','evidence':name,'state':'observed'})
        from .stack import discover
        return {'stack':discover(self.root),'schema':1,'components':components,'findings':findings,'environment_names':sorted(env),'resources':resources,'commands':commands,'limitations':['Static discovery is incomplete; resource edges and commands require runtime verification.']}


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

    def patch(self, files):
        contract=self.check_contract()
        if not isinstance(files,dict) or not files or len(files)>128:
            raise PolicyError('repair must be a nonempty path/content map of at most 128 files')
        if self.state['phase'] not in {'baseline','partial','blocked','repaired'}:
            raise PolicyError('repair requires recorded baseline')
        if self.state['attempts']>=self.state['max_attempts']:
            raise PolicyError('repair attempt budget exhausted')
        canonical_names=set(); total=0
        for name, content in files.items():
            if not isinstance(name,str): raise PolicyError('repair paths must be strings')
            safe_path(self.root/'baseline',name)
            canonical=PurePosixPath(name)
            if canonical in canonical_names: raise PolicyError('duplicate normalized repair path')
            canonical_names.add(canonical)
            if any(canonical == PurePosixPath(protected) or PurePosixPath(protected) in canonical.parents for protected in contract.get('protected_paths',[])):
                raise PolicyError('repair cannot change acceptance input')
            if excluded(name) or not isinstance(content,str) or len(content.encode())>4*1024*1024:
                raise PolicyError('excluded or oversized repair file')
            if secret_like(content):
                raise PolicyError('repair includes recognizable credential material; use synthetic configuration')
            total+=len(content.encode())
            if total>16*1024*1024: raise PolicyError('repair size budget exceeded')
        attempt=self.state['attempts']+1; repair=self.root/('repair-'+str(attempt))
        shutil.copytree(self.root/'baseline',repair)
        for name,content in files.items():
            p=safe_path(repair,name); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(content)
        runtime_modes(repair)
        _register_snapshot(repair)
        import difflib
        diff=[]
        for name in sorted(files):
            before=self.root/'baseline'/name
            diff.extend(difflib.unified_diff(before.read_text().splitlines(True) if before.exists() else [],files[name].splitlines(True),fromfile='a/'+name,tofile='b/'+name))
        (self.root/('repair-'+str(attempt)+'.diff')).write_text(''.join(diff))
        self.state.update(attempts=attempt,repair=str(repair),repair_digest=tree_digest(repair))
        self.transition('repaired','repair-'+str(attempt)+'.diff')
        return {'workspace':str(repair),'digest':self.state['repair_digest'],'diff':str(self.root/('repair-'+str(attempt)+'.diff'))}

    def verify(self, backend, image=None):
        contract=self.check_contract()
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
        if tree_digest(repair)!=self.state['repair_digest']:
            raise PolicyError('source changed during verification')
        write_json(self.root/'verification.json',results)
        self.transition('verified' if all(r['passed'] for r in results) else 'partial','verification.json')
        return {'status':self.state['phase'],'results':results,'snapshot':self.state['repair_digest']}

    def report(self):
        self.check_contract()
        return {'run':self.state,'onboarding':self.state['phase'],'everyday_development':'unverified unless acceptance includes edit/test cycle','real_provider_fidelity':'unverified','limitations':['Harness filesystem access is not constrained by this helper. Controller state must remain inaccessible to untrusted agents.','Verification certifies only the frozen checks; supply independent assertions from known contracts.']}
