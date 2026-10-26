"""Explicit native command execution. Host permissions apply; this is NOT a sandbox."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from .core import PolicyError, redact, validate_runtime_input


def environment():
    # Avoid forwarding ambient credential variables. Native code can still read host files/network.
    return {k:v for k,v in os.environ.items() if k in {'PATH','LANG','LC_ALL','SYSTEMROOT','TMPDIR'}}


def terminate_group(process):
    # A dead leader does not imply that its descendants exited. Signal and inspect
    # the owned process group independently of wait() on the leader.
    try: os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError:
        process.wait(); return
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        process.poll()
        try:os.killpg(process.pid,0)
        except ProcessLookupError:
            process.wait(); return
        time.sleep(.05)
    try:os.killpg(process.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    process.wait()


class NativeBackend:
    requires_image=False

    def execute(self, workspace, image, argv, timeout=60):
        if not isinstance(timeout,int) or not 1<=timeout<=300:
            raise PolicyError('timeout must be 1..300 seconds')
        if not argv or not all(isinstance(x,str) and '\x00' not in x for x in argv):
            raise PolicyError('command must be nonempty string argv')
        if os.name!='posix':raise PolicyError('native process-group controller currently requires POSIX')
        workspace=validate_runtime_input(workspace);started=time.monotonic();outcome='completed'
        with tempfile.TemporaryDirectory(prefix='initloop-native-') as tmp, tempfile.TemporaryFile() as log:
            work=Path(tmp)/'project';shutil.copytree(workspace,work)
            process=subprocess.Popen(argv,cwd=work,env=environment(),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            try:
                while process.poll() is None:
                    if time.monotonic()-started>timeout:outcome='timeout';break
                    if os.fstat(log.fileno()).st_size>1024*1024:outcome='output-limit';break
                    time.sleep(.05)
                if os.fstat(log.fileno()).st_size>1024*1024:outcome='output-limit'
            finally:
                # Also reap background children even when the command itself has exited.
                terminate_group(process)
            log.seek(0);output=redact(log.read(1024*1024).decode(errors='replace'))
        return {'exit_code':process.returncode if outcome=='completed' else 124,'stdout':output,'outcome':outcome,
                'cleanup':'removed','elapsed_seconds':round(time.monotonic()-started,3),'runner':'native','sandboxed':False,
                'network':'host; unrestricted by helper','writes':'disposable working copy; host access unrestricted',
                'command':redact(repr(argv))}
