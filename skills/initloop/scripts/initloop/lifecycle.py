"""Owned native foreground development processes; no sandbox or daemon orchestration."""
import fcntl
from contextlib import contextmanager
import stat
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import threading
import uuid

from .core import PolicyError, redact, secret_like, write_json
from .native import environment, terminate_group


def private_open(path, append=False):
    """Never follow/truncate a pre-existing link at a controller write path."""
    try:fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|(os.O_APPEND if append else 0),0o600)
    except OSError as e:raise PolicyError('unsafe controller file: '+str(path)) from e
    if not stat.S_ISREG(os.fstat(fd).st_mode) or os.fstat(fd).st_nlink!=1:
        os.close(fd);raise PolicyError('controller file must be a private regular file')
    os.fchmod(fd,0o600)
    return os.fdopen(fd,'ab' if append else 'r+b',buffering=0)


@contextmanager
def locked(path):
    with private_open(path) as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        yield


def normalized_identity(value):
    # macOS Python launchers may re-exec a framework binary; retain the stable
    # birth time and unique controller arguments, not the interpreter path.
    birth=re.match(r'\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4}',value)
    marker=' -m initloop.lifecycle _serve '
    if birth and marker in value:
        return birth.group(0)+marker+value.split(marker,1)[1]
    return value


def identity(pid):
    p=subprocess.run(['/bin/ps','-p',str(pid),'-o','lstart=','-o','command='],capture_output=True,text=True)
    return normalized_identity(p.stdout.strip()) if p.returncode==0 else ''


class Service:
    def __init__(self,ledger,name):
        if os.name!='posix':raise PolicyError('native lifecycle currently requires POSIX')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',name):raise PolicyError('invalid service name')
        original=Path(ledger).absolute()
        if original.is_symlink():raise PolicyError('symlink ledger is not allowed')
        self.ledger=original.resolve();self.root=self.ledger/name
        self.record=self.root/'service.json';self.data=self.root/'data';self.name=name

    def _load(self):
        if self.root.is_symlink() or self.record.is_symlink() or not self.record.is_file():raise PolicyError('owned service record required')
        row=json.loads(self.record.read_text())
        if row.get('purpose')!='initloop-native-service' or not re.fullmatch('[0-9a-f]{32}',row.get('owner','')):
            raise PolicyError('invalid ownership record')
        if self.data.is_symlink():raise PolicyError('owned data cannot be a symlink')
        return row

    def _running(self,row):
        pid=row.get('pid');stamp=row.get('identity')
        return bool(pid and stamp and identity(pid)==normalized_identity(stamp))

    def status(self):
        row=self._load()
        return {'status':('running' if row.get('started') else 'starting') if self._running(row) else 'stopped','name':self.name,'project':row['project'],
                'pid':row.get('pid'),'data':str(self.data),'runner':'native','sandboxed':False,
                'scope':'owned foreground supervisor/process group only; daemonized or external services are not managed'}

    def start(self,project,argv):
        project=Path(project).resolve(strict=True)
        if not project.is_dir():raise PolicyError('project must be a directory')
        if self.ledger==project or project in self.ledger.parents or self.ledger in project.parents:
            raise PolicyError('service ledger must be outside project and its ancestors')
        if not argv or not all(isinstance(a,str) and '\x00' not in a for a in argv):raise PolicyError('nonempty argv required')
        if secret_like(' '.join(argv)):raise PolicyError('do not put credentials in command arguments')
        self.ledger.mkdir(parents=True,exist_ok=True,mode=0o700)
        with locked(self.ledger/(self.name+'.lock')):
            if self.root.exists():
                row=self._load()
                if self._running(row):raise PolicyError('owned service already running')
                if row['project']!=str(project):raise PolicyError('service name belongs to a different project')
            else:
                self.root.mkdir(mode=0o700);row={'purpose':'initloop-native-service','owner':uuid.uuid4().hex}
            for log_name in ('supervisor.log','service.log'):
                with private_open(self.root/log_name,append=True):pass
            self.data.mkdir(mode=0o700,exist_ok=True)
            row.update(project=str(project),argv=argv,pid=None,identity=None,started=False)
            write_json(self.record,row)
            env=environment();env['PYTHONPATH']=str(Path(__file__).resolve().parents[1])
            with private_open(self.root/'supervisor.log',append=True) as log:
                p=subprocess.Popen([sys.executable,'-m','initloop.lifecycle','_serve',str(self.record)],env=env,
                                   stdin=subprocess.DEVNULL,stdout=log,stderr=log,start_new_session=True)
            row.update(pid=p.pid,identity=identity(p.pid))
            write_json(self.record,row)
            threading.Thread(target=p.wait,daemon=True).start()
            for _ in range(100):
                current=self._load()
                if current.get('started'):return self.status()
                if p.poll() is not None:raise PolicyError('native supervisor failed; inspect supervisor.log')
                time.sleep(.02)
            return self.status()  # Owned starting state; duplicate start/reset remain refused.

    def stop(self):
        self._load()
        with locked(self.ledger/(self.name+'.lock')):
            row=self._load()
            if not self._running(row):return self.status()
            # Exact supervisor identity, serialized with initialization and reset.
            try:os.kill(row['pid'],signal.SIGTERM)
            except ProcessLookupError:return self.status()
            for _ in range(100):
                if not self._running(row):return self.status()
                time.sleep(.05)
            raise PolicyError('supervisor stop pending; no unrelated process was signalled')

    def logs(self):
        self._load();path=self.root/'service.log'
        if path.is_symlink():raise PolicyError('symlink log refused')
        if not path.exists():return {'stdout':''}
        with path.open('rb') as f:
            f.seek(max(0,path.stat().st_size-65536));content=f.read(65536)
        return {'stdout':redact(content.decode(errors='replace'))}

    def reset(self):
        self._load()
        with locked(self.ledger/(self.name+'.lock')):
            row=self._load()
            if self._running(row):raise PolicyError('stop the owned service before resetting data')
            # Only the exact helper-owned data directory, never source or arbitrary reset commands.
            import shutil
            if self.data.exists():shutil.rmtree(self.data)
            self.data.mkdir(mode=0o700)
            return {'status':'reset','data':str(self.data),'scope':'helper-owned data only; project/external databases unchanged'}


def serve(record):
    record=Path(record);root=record.parent
    # Parent registers exact supervisor identity before a potentially slow child launch.
    for _ in range(250):
        row=json.loads(record.read_text())
        if row.get('pid')==os.getpid():break
        time.sleep(.02)
    else:raise PolicyError('supervisor ownership initialization missing')
    stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    env=environment();env['INITLOOP_DATA_DIR']=str(root/'data');env['PYTHONUNBUFFERED']='1'
    # Raw application logs are local private files; retrieval redacts best effort. Do not log secrets.
    with private_open(root/'service.log',append=True) as log:
        os.chmod(root/'service.log',0o600)
        p=subprocess.Popen(row['argv'],cwd=row['project'],env=env,stdin=subprocess.DEVNULL,
                           stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        row.update(started=True,child_pid=p.pid,identity=identity(os.getpid()));write_json(record,row)
        try:
            while p.poll() is None and not stopping:time.sleep(.05)
        finally:
            terminate_group(p)
            row.update(pid=None,identity=None,exit_code=p.returncode);write_json(record,row)


if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[1]!='_serve':raise SystemExit(2)
    serve(sys.argv[2])
