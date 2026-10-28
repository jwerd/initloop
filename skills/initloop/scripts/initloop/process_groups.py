"""Birth identities and live-member inspection for owned native process groups."""
import os
from pathlib import Path
import subprocess
import sys

from .core import PolicyError


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
        process = subprocess.run(['/bin/ps', '-p', str(pid), '-o', 'lstart=', '-o', 'command='], capture_output=True, text=True)
        return process.stdout.strip() if process.returncode == 0 else ''
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


def remember_group(group, known, process=None):
    """Extend witnesses only while a recorded birth identity proves ownership."""
    members = group_members(group)
    if not members:
        return members
    current = {str(pid): process_token(pid) for pid in members}
    # A directly owned unreaped child cannot have its PID reused, even when
    # macOS no longer exposes its birth token during the zombie transition.
    owned = process is not None and process.returncode is None
    for text_pid, stamp in list(known.items()):
        pid = int(text_pid)
        token = process_token(pid)
        if token and stamp == token:
            try:
                if os.getpgid(pid) == group:
                    owned = True
                    break
            except ProcessLookupError:
                pass
    if not owned:
        raise PolicyError('remaining group ownership is unproven; no signal sent')
    known.update({pid: token for pid, token in current.items() if token})
    return members
