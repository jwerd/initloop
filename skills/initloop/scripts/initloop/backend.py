"""Optional constrained disposable Docker backend. Images must already be available locally."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
from typing import Protocol

from .core import PolicyError, redact, write_json, validate_runtime_input


class RuntimeBackend(Protocol):
    def execute(self, workspace: Path, image: str, argv: list, timeout: int=60) -> dict: ...


class DockerBackend:
    def __init__(self, ledger=None):
        self.ledger=Path(ledger) if ledger is not None else Path(tempfile.gettempdir())/('initloop-owned-'+str(os.getuid()))

    def cleanup(self):
        """Recover recorded resources after controller interruption, without global pruning."""
        results=[]
        if not self.ledger.exists(): return results
        if self.ledger.is_symlink(): raise PolicyError('resource ledger cannot be a symlink')
        import json
        for path in sorted(self.ledger.glob('initloop-*.json')):
            if path.is_symlink(): raise PolicyError('resource record cannot be a symlink')
            row=json.loads(path.read_text()); name=row['name']; owner=row['owner']
            if not re.fullmatch(r'initloop-[0-9a-f]{32}',name) or not re.fullmatch(r'[0-9a-f]{32}',owner):
                raise PolicyError('invalid owned resource record')
            inspect=subprocess.run(['docker','inspect','--format','{{index .Config.Labels "initloop.owner"}}',name],capture_output=True,text=True,timeout=15)
            if inspect.returncode or inspect.stdout.strip()!=owner:
                results.append({'name':name,'status':'unavailable' if inspect.returncode else 'ownership-mismatch'}); continue
            removed=subprocess.run(['docker','rm','-f',name],capture_output=True,text=True,timeout=15)
            if removed.returncode==0: path.unlink()
            results.append({'name':name,'status':'removed' if removed.returncode==0 else 'cleanup-failed'})
        return results

    def command(self, workspace, image, argv, name, owner=None):
        workspace=Path(workspace).resolve()
        if ',' in str(workspace) or '\n' in str(workspace):
            raise PolicyError('invalid mount path')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image):
            raise PolicyError('runtime image must resolve to an immutable local image ID')
        if not argv or not all(isinstance(x,str) and '\x00' not in x for x in argv):
            raise PolicyError('command must be nonempty string argv')
        # Read-only input; all process writes live in owned tmpfs, never a host bind.
        return ['docker','run','--pull=never','--name',name,'--label','initloop.owned=true','--label','initloop.owner='+(owner or name.removeprefix('initloop-')),'--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=96','--memory=512m','--cpus=1','--user=65534:65534','--init','--mount','type=bind,src='+str(workspace)+',dst=/input,readonly','--tmpfs','/workspace:rw,exec,nosuid,nodev,size=268435456,mode=1777','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777','--workdir=/workspace','--env','HOME=/tmp', '--entrypoint=/bin/sh',image,'-c','cp -R /input/. /workspace/ && exec "$@"','initloop',*argv]

    def execute(self, workspace, image, argv, timeout=60):
        if not isinstance(timeout,int) or not 1<=timeout<=300:
            raise PolicyError('timeout must be 1..300 seconds')
        workspace=validate_runtime_input(workspace)
        probe=subprocess.run(['docker','image','inspect','--format','{{.Id}}',image],capture_output=True,text=True,timeout=15)
        if probe.returncode:
            raise PolicyError('local Docker image unavailable; prepare dependencies separately, no host fallback')
        image_id=probe.stdout.strip(); name='initloop-'+uuid.uuid4().hex; owner=uuid.uuid4().hex
        command=self.command(workspace,image_id,argv,name,owner); started=time.monotonic()
        if self.ledger.is_symlink(): raise PolicyError('resource ledger cannot be a symlink')
        self.ledger.mkdir(parents=True,exist_ok=True,mode=0o700)
        record=self.ledger/(name+'.json'); write_json(record,{'name':name,'owner':owner})
        outcome='completed'; code=None; output=''
        with tempfile.TemporaryFile() as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            try:
                while process.poll() is None:
                    if time.monotonic()-started>timeout:
                        outcome='timeout'; break
                    if os.fstat(log.fileno()).st_size>1024*1024:
                        outcome='output-limit'; break
                    time.sleep(.05)
                if os.fstat(log.fileno()).st_size>1024*1024:
                    outcome='output-limit'
                if outcome!='completed':
                    process.terminate()
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                code=process.returncode
            finally:
                # Exact random name, never global prune or destructive project commands.
                try:
                    cleanup=subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                    if cleanup.returncode==0: record.unlink(missing_ok=True)
                except (OSError,subprocess.SubprocessError):
                    pass  # Keep durable record for explicit recovery; never claim cleanup passed.
                if process.poll() is None:
                    process.kill(); process.wait()
                log.seek(0); output=redact(log.read(1024*1024).decode(errors='replace'))
        return {'exit_code':code if outcome=='completed' else 124,'stdout':output,'outcome':outcome,'cleanup':'removed' if not record.exists() else 'pending-recovery','elapsed_seconds':round(time.monotonic()-started,3),'image_id':image_id,'network':'none','writes':'disposable tmpfs','command':redact(repr(argv))}
