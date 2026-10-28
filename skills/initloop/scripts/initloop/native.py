"""Explicit native command execution. Host permissions apply; this is NOT a sandbox."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from .core import PolicyError, redact, validate_runtime_input, write_json
from .process_groups import group_members, process_token, remember_group


def environment():
    # Avoid forwarding ambient credential variables. Native code can still read host files/network.
    return {k:v for k,v in os.environ.items() if k in {'PATH','LANG','LC_ALL','SYSTEMROOT','TMPDIR'}}


def terminate_group(process, known):
    """Signal only a birth-identified group and prove its live members gone."""
    # Caller captured the leader's identity before polling/reaping it and kept
    # descendant witnesses while the group was provably owned.
    def members():
        # Keep these lookups local so every signal gets a fresh ownership check.
        live = group_members(process.pid)
        if live:
            owned = process.returncode is None
            current = {str(pid): process_token(pid) for pid in live}
            for text_pid, stamp in list(known.items()):
                pid = int(text_pid)
                if stamp and process_token(pid) == stamp:
                    try:
                        if os.getpgid(pid) == process.pid:
                            owned = True
                            break
                    except ProcessLookupError:
                        pass
            if not owned:
                raise PolicyError('remaining group ownership is unproven; no signal sent')
            known.update({pid: token for pid, token in current.items() if token})
        return live

    def send(sig):
        if not members():
            return
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        except PermissionError:
            # macOS may transiently report EPERM while a killed group exits.
            # Only a separate process-table proof can establish completion.
            if group_members(process.pid):
                raise PolicyError('owned process-group cleanup is unproven after permission failure')

    send(signal.SIGTERM)
    deadline = time.monotonic() + 3
    while group_members(process.pid):
        if time.monotonic() >= deadline:
            break
        time.sleep(.05)
    if group_members(process.pid):
        send(signal.SIGKILL)
        deadline = time.monotonic() + 2
        while group_members(process.pid):
            if time.monotonic() >= deadline:
                raise PolicyError('owned process-group cleanup is still pending')
            time.sleep(.02)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired as error:
        raise PolicyError('owned leader cleanup is still pending') from error


class NativeBackend:
    requires_image=False

    def execute(self, workspace, image, argv, timeout=60):
        if not isinstance(timeout,int) or not 1<=timeout<=300:
            raise PolicyError('timeout must be 1..300 seconds')
        if not argv or not all(isinstance(x,str) and '\x00' not in x for x in argv):
            raise PolicyError('command must be nonempty string argv')
        if os.name!='posix':raise PolicyError('native process-group controller currently requires POSIX')
        workspace=validate_runtime_input(workspace);started=time.monotonic();outcome='completed'
        # mkdtemp has no finalizer: unresolved work must survive stack unwinding.
        tmp = Path(tempfile.mkdtemp(prefix='initloop-native-'))
        work = tmp / 'project'
        process = None
        known = {}
        cleanup_error = None
        try:
            with tempfile.TemporaryFile() as log:
                shutil.copytree(workspace, work)
                # Popen can be interrupted after spawning but before returning a
                # handle. Retain unknown launch state until cleanup is proven.
                cleanup_error = 'native launch cleanup has not been proven'
                pending_record = {
                    'purpose': 'initloop-native-cleanup-pending',
                    'working_copy': str(work), 'launch_state': 'unknown',
                    'child_pid': None, 'child_pgid': None, 'child_identity': None,
                    'group_identities': {}, 'cleanup_error': cleanup_error,
                    'recovery': 'manual inspection required; launch ownership is not registered; no saved PID/group can be safely signalled',
                }
                write_json(tmp / 'recovery.json', pending_record)
                try:
                    process = subprocess.Popen(argv, cwd=work, env=environment(), stdout=log,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                except BaseException as error:
                    write_json(tmp / 'recovery.json', {
                        'purpose': 'initloop-native-cleanup-pending',
                        'working_copy': str(work), 'launch_state': 'unknown',
                        'child_pid': None, 'child_pgid': None, 'child_identity': None,
                        'group_identities': {},
                        'cleanup_error': redact(str(error) or type(error).__name__),
                        'recovery': 'manual inspection required; launch interrupted before ownership registration; no saved PID/group can be safely signalled',
                    })
                    raise
                try:
                    known[str(process.pid)] = process_token(process.pid)
                    pending_record.update(launch_state='launched', child_pid=process.pid,
                                          child_pgid=process.pid,
                                          child_identity=known[str(process.pid)],
                                          group_identities=known)
                    write_json(tmp / 'recovery.json', pending_record)
                    while True:
                        remember_group(process.pid, known, process)
                        if process.poll() is not None:
                            break
                        if time.monotonic()-started>timeout:outcome='timeout';break
                        if os.fstat(log.fileno()).st_size>1024*1024:outcome='output-limit';break
                        time.sleep(.05)
                    if os.fstat(log.fileno()).st_size>1024*1024:outcome='output-limit'
                finally:
                    try:
                        terminate_group(process, known)
                        cleanup_error = None
                    except BaseException as error:
                        cleanup_error = redact(str(error) or type(error).__name__)
                        write_json(tmp / 'recovery.json', {
                            'purpose': 'initloop-native-cleanup-pending',
                            'working_copy': str(work), 'child_pid': process.pid,
                            'child_pgid': process.pid, 'child_identity': known.get(str(process.pid)),
                            'group_identities': known, 'cleanup_error': cleanup_error,
                            'recovery': 'manual inspection required; prove recorded birth identities and live group absence before removal',
                        })
                        if not isinstance(error, Exception):
                            raise
                log.seek(0);output=redact(log.read(1024*1024).decode(errors='replace'))
        except BaseException as error:
            if cleanup_error:
                raise PolicyError('cleanup unproven; retained working copy: {}; recovery record: {}'.format(
                    work, tmp / 'recovery.json')) from error
            raise
        finally:
            if not cleanup_error:
                shutil.rmtree(tmp)
        result = {'exit_code':process.returncode if outcome=='completed' else 124,'stdout':output,'outcome':outcome,
                  'cleanup':'removed','elapsed_seconds':round(time.monotonic()-started,3),'runner':'native','sandboxed':False,
                  'network':'host; unrestricted by helper','writes':'disposable working copy; host access unrestricted',
                  'command':redact(repr(argv))}
        if cleanup_error:
            result.update(exit_code=125, outcome='cleanup-pending', cleanup='retained',
                          retained_work=str(work), recovery_record=str(tmp / 'recovery.json'),
                          cleanup_error=cleanup_error,
                          recovery='manual inspection required; validate recovery record birth identities and prove live group absence before removing retained work')
        return result
