"""Owned native foreground development processes; no sandbox or daemon orchestration."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

from .core import PolicyError, redact, secret_like, write_json
from .native import environment, terminate_group


def private_open(path, append=False):
    """Never follow/truncate a pre-existing link at a controller write path."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    if append:
        flags |= os.O_APPEND
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise PolicyError('unsafe controller file: ' + str(path)) from error
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise PolicyError('controller file must be a private regular file')
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'ab' if append else 'r+b', buffering=0)


@contextmanager
def locked(path):
    with private_open(path) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def normalized_identity(value):
    # macOS Python launchers may re-exec a framework binary; retain the stable
    # birth time and unique controller arguments, not the interpreter path.
    birth = re.match(r'\w{3} \w{3}\s+\d+ \d{2}:\d{2}:\d{2} \d{4}', value)
    marker = ' -m initloop.lifecycle _serve '
    if birth and marker in value:
        return birth.group(0) + marker + value.split(marker, 1)[1]
    return value


def identity(pid):
    process = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart=', '-o', 'command='],
                             capture_output=True, text=True)
    return normalized_identity(process.stdout.strip()) if process.returncode == 0 else ''


def process_token(pid):
    """Kernel birth identity, stable across exec and distinct from a reused PID.

    macOS exposes microsecond creation time through libproc. Linux exposes
    creation ticks and a boot UUID through procfs. Other POSIX systems retain
    exact ps identity, so an exec may conservatively require manual recovery.
    """
    try:
        if sys.platform == 'darwin':
            import ctypes

            class BsdInfo(ctypes.Structure):
                _fields_ = [('prefix', ctypes.c_uint32 * 12),
                            ('comm', ctypes.c_char * 16), ('name', ctypes.c_char * 32),
                            ('middle', ctypes.c_uint32 * 6),
                            ('seconds', ctypes.c_uint64), ('microseconds', ctypes.c_uint64)]

            library = ctypes.CDLL('/usr/lib/libproc.dylib')
            library.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                            ctypes.c_void_p, ctypes.c_int]
            library.proc_pidinfo.restype = ctypes.c_int
            info = BsdInfo()
            size = ctypes.sizeof(info)
            if library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), size) != size:
                return ''
            return 'darwin:{}:{}'.format(info.seconds, info.microseconds)
        if sys.platform.startswith('linux'):
            fields = Path('/proc/{}/stat'.format(pid)).read_text().rsplit(')', 1)[1].split()
            boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            return 'linux:{}:{}'.format(boot, fields[19])
        return identity(pid)
    except (OSError, ValueError, IndexError):
        return ''


def group_members(pgid):
    """Inspect live members independently of the supervisor and group leader.

    Zombies cannot access retained data and must be reaped by their OS parent.
    Failure to inspect is an error, never evidence that a group has stopped.
    """
    process = subprocess.run(['/bin/ps', '-axo', 'pid=,pgid=,stat='], capture_output=True, text=True)
    if process.returncode:
        raise PolicyError('cannot inspect owned process group; cleanup is unproven')
    members = []
    for line in process.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
            if int(fields[1]) == pgid and not fields[2].startswith('Z'):
                members.append(int(fields[0]))
    return members


def owned_child(row):
    pid = row.get('child_pid')
    pgid = row.get('child_pgid')
    stamp = row.get('child_identity')
    if not (isinstance(pid, int) and pid > 1 and pid == pgid and stamp):
        return False
    try:
        return os.getpgid(pid) == pgid and process_token(pid) == stamp
    except ProcessLookupError:
        return False


class Service:
    def __init__(self, ledger, name):
        if os.name != 'posix':
            raise PolicyError('native lifecycle currently requires POSIX')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
            raise PolicyError('invalid service name')
        original = Path(ledger).absolute()
        if original.is_symlink():
            raise PolicyError('symlink ledger is not allowed')
        self.ledger = original.resolve()
        self.root = self.ledger / name
        self.record = self.root / 'service.json'
        self.data = self.root / 'data'
        self.name = name

    def _load(self):
        if self.root.is_symlink() or self.record.is_symlink() or not self.record.is_file():
            raise PolicyError('owned service record required')
        row = json.loads(self.record.read_text())
        if row.get('purpose') != 'initloop-native-service' or not re.fullmatch('[0-9a-f]{32}', row.get('owner', '')):
            raise PolicyError('invalid ownership record')
        if self.data.is_symlink():
            raise PolicyError('owned data cannot be a symlink')
        return row

    def _running(self, row):
        pid = row.get('pid')
        stamp = row.get('identity')
        token = row.get('supervisor_token')
        if token:
            return bool(pid and process_token(pid) == token)
        return bool(pid and stamp and identity(pid) == normalized_identity(stamp))

    def _state(self, row):
        if self._running(row):
            return 'running' if row.get('started') else 'starting'
        child = row.get('child_pid')
        group = row.get('child_pgid', child)
        if isinstance(group, int) and group > 1:
            if not group_members(group):
                return 'stopped'
            return 'orphaned' if owned_child(row) else 'unknown'
        # The write-ahead marker precedes Popen. If the supervisor disappeared
        # in the launch/ownership-record gap, there may be an unrecorded child.
        if row.get('launch_state') == 'launching' or row.get('started'):
            return 'unknown'
        return 'stopped'

    def status(self):
        row = self._load()
        state = self._state(row)
        return {
            'status': state, 'name': self.name, 'project': row['project'],
            'pid': row.get('pid'), 'child_pid': row.get('child_pid'),
            'data': str(self.data), 'runner': 'native', 'sandboxed': False,
            'scope': 'owned foreground supervisor/process group only; daemonized or external services are not managed',
            'recovery': ('stop can recover the independently identified child group' if state == 'orphaned' else
                         'cleanup unproven; inspect owned resources before manual recovery' if state == 'unknown' else None),
        }

    def start(self, project, argv):
        project = Path(project).resolve(strict=True)
        if not project.is_dir():
            raise PolicyError('project must be a directory')
        if self.ledger == project or project in self.ledger.parents or self.ledger in project.parents:
            raise PolicyError('service ledger must be outside project and its ancestors')
        if not argv or not all(isinstance(arg, str) and '\x00' not in arg for arg in argv):
            raise PolicyError('nonempty argv required')
        if secret_like(' '.join(argv)):
            raise PolicyError('do not put credentials in command arguments')
        self.ledger.mkdir(parents=True, exist_ok=True, mode=0o700)
        with locked(self.ledger / (self.name + '.lock')):
            if self.root.exists():
                row = self._load()
                if self._state(row) != 'stopped':
                    raise PolicyError('owned service is active or cleanup is unproven; stop/recover it first')
                if row['project'] != str(project):
                    raise PolicyError('service name belongs to a different project')
            else:
                self.root.mkdir(mode=0o700)
                row = {'purpose': 'initloop-native-service', 'owner': uuid.uuid4().hex}
            for log_name in ('supervisor.log', 'service.log'):
                with private_open(self.root / log_name, append=True):
                    pass
            self.data.mkdir(mode=0o700, exist_ok=True)
            row.update(project=str(project), argv=argv, pid=None, identity=None, supervisor_token=None, started=False,
                       child_pid=None, child_pgid=None, child_identity=None, launch_state='preparing')
            write_json(self.record, row)
            env = environment()
            env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1])
            with private_open(self.root / 'supervisor.log', append=True) as log:
                process = subprocess.Popen(
                    [sys.executable, '-m', 'initloop.lifecycle', '_serve', str(self.record)],
                    env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
            try:
                row.update(pid=process.pid, identity=identity(process.pid),
                           supervisor_token=process_token(process.pid))
                if not row['supervisor_token']:
                    raise PolicyError('could not establish supervisor birth identity')
                write_json(self.record, row)
            except BaseException:
                # This Popen object is ours; the unregistered supervisor cannot
                # launch an application. Do not leave it waiting on registration.
                process.terminate()
                process.wait()
                raise
            threading.Thread(target=process.wait, daemon=True).start()
            for _ in range(100):
                current = self._load()
                if current.get('started'):
                    return self.status()
                if process.poll() is not None:
                    raise PolicyError('native supervisor failed; inspect supervisor.log')
                time.sleep(.02)
            return self.status()

    def _stop_orphan(self, row):
        if not owned_child(row):
            raise PolicyError('owned child identity changed; no process was signalled')
        group = row['child_pgid']
        # Capture live identities before signalling. A dead leader is not proof
        # that its descendants exited; a stale/reused group is never signalled.
        known = {pid: process_token(pid) for pid in group_members(group)}
        if not owned_child(row):
            raise PolicyError('owned child identity changed; no process was signalled')
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if not group_members(group):
                return
            time.sleep(.05)
        members = group_members(group)
        if not any(known.get(pid) and process_token(pid) == known[pid] for pid in members):
            raise PolicyError('remaining group ownership is unproven; no further signal sent')
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            return
        for _ in range(100):
            if not group_members(group):
                return
            time.sleep(.02)
        raise PolicyError('owned process-group cleanup is still pending')

    def stop(self):
        self._load()
        with locked(self.ledger / (self.name + '.lock')):
            row = self._load()
            state = self._state(row)
            if state == 'unknown':
                raise PolicyError('service ownership is unknown; inspect owned resources before manual recovery')
            if state in {'running', 'starting'}:
                if not self._running(row):
                    raise PolicyError('supervisor identity changed; retry recovery')
                try:
                    os.kill(row['pid'], signal.SIGTERM)
                except ProcessLookupError:
                    pass
                for _ in range(100):
                    row = self._load()
                    if not self._running(row):
                        break
                    time.sleep(.05)
                else:
                    raise PolicyError('supervisor stop pending; no unrelated process was signalled')
                state = self._state(row)
            if state == 'orphaned':
                self._stop_orphan(row)
            if self._state(self._load()) != 'stopped':
                raise PolicyError('service cleanup is unproven; reset and restart remain blocked')
            row = self._load()
            row.update(pid=None, identity=None, supervisor_token=None, started=False, child_pid=None,
                       child_pgid=None, child_identity=None, launch_state='stopped')
            write_json(self.record, row)
            return self.status()

    def logs(self):
        self._load()
        path = self.root / 'service.log'
        if path.is_symlink():
            raise PolicyError('symlink log refused')
        if not path.exists():
            return {'stdout': ''}
        with path.open('rb') as log:
            log.seek(max(0, path.stat().st_size - 65536))
            content = log.read(65536)
        return {'stdout': redact(content.decode(errors='replace'))}

    def reset(self):
        self._load()
        with locked(self.ledger / (self.name + '.lock')):
            if self._state(self._load()) != 'stopped':
                raise PolicyError('stop/recover the owned service before resetting data; cleanup must be proven')
            # Only the exact helper-owned directory, never arbitrary reset commands.
            import shutil
            if self.data.exists():
                shutil.rmtree(self.data)
            self.data.mkdir(mode=0o700)
            return {'status': 'reset', 'data': str(self.data),
                    'scope': 'helper-owned data only; project/external databases unchanged'}


def serve(record):
    record = Path(record)
    root = record.parent
    # Parent registers exact supervisor identity before a potentially slow launch.
    for _ in range(250):
        row = json.loads(record.read_text())
        if row.get('pid') == os.getpid():
            break
        time.sleep(.02)
    else:
        raise PolicyError('supervisor ownership initialization missing')
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    env = environment()
    env['INITLOOP_DATA_DIR'] = str(root / 'data')
    env['PYTHONUNBUFFERED'] = '1'
    # Raw logs are private; retrieval redacts best effort. Do not log secrets.
    with private_open(root / 'service.log', append=True) as log:
        row.update(launch_state='launching')
        write_json(record, row)
        process = None
        try:
            if not stopping:
                process = subprocess.Popen(row['argv'], cwd=row['project'], env=env,
                                           stdin=subprocess.DEVNULL, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                row.update(started=True, child_pid=process.pid, child_pgid=process.pid,
                           child_identity=process_token(process.pid), launch_state='running',
                           identity=identity(os.getpid()))
                write_json(record, row)
                while process.poll() is None and not stopping:
                    time.sleep(.05)
        finally:
            # Includes launch bookkeeping failure. If SIGKILL prevents this,
            # the write-ahead marker keeps status unknown instead of stopped.
            if process is not None:
                try:
                    terminate_group(process)
                except PermissionError:
                    # macOS can return EPERM for killpg(..., 0) while a killed
                    # group disappears. Only suppress it after an independent
                    # process-table check proves there are no live members.
                    if group_members(process.pid):
                        raise
                    process.wait()
            row.update(pid=None, identity=None, supervisor_token=None, started=False, child_pid=None,
                       child_pgid=None, child_identity=None, launch_state='stopped',
                       exit_code=process.returncode if process else None)
            write_json(record, row)


if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] != '_serve':
        raise SystemExit(2)
    serve(sys.argv[2])
