"""Permitted working-tree text discovery; never follows symlink target contents.

This read-only inventory is deliberately separate from snapshot/copy/execution
validation. Skipping an input is reported, never permission to copy or execute it.
"""
import errno
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat

_IGNORED={'.git','.ssh','.aws','node_modules','vendor','.venv','venv','__pycache__','.initloop','dist','build'}
_SECRET=re.compile(r'(^\.env($|\.)|secret|credential|\.pem$|\.key$|id_rsa|^\.npmrc$|^auth\.json$)',re.I)
_MAX=1024*1024
_UNRESOLVED=object()


def _excluded(name,parent):
    template=name in {'.env.example','.env.sample','.env.template'}
    return (name in _IGNORED or name in {'.netrc','.pypirc'} or
            PurePosixPath(name).suffix.lower() in {'.p12','.sqlite','.sqlite3','.db','.log'} or
            (_SECRET.search(name) and not template) or
            (name=='skills' and parent.parts and parent.parts[-1] in {'.agents','.claude','.codex'}))


def _target(root,source,value):
    """Normalize link text lexically; never resolve/stat an outside path."""
    # Collapsing alias/../path before inspecting alias can invent an internal
    # target when alias points outside. Only leading relative parent segments
    # have a known no-link source-directory base in this bounded classifier.
    seen_component=False
    for part in PurePosixPath(value).parts:
        if part=='..' and seen_component:return _UNRESOLVED
        if part not in {'.','..','/'}:seen_component=True
    if os.path.isabs(value):
        normalized=os.path.normpath(value)
        if normalized==str(root):return '.'
        prefix=str(root)+os.sep
        return normalized[len(prefix):] if normalized.startswith(prefix) else None
    normalized=posixpath.normpath(posixpath.join(str(PurePosixPath(source).parent),value))
    return None if normalized=='..' or normalized.startswith('../') else normalized


def _link_kind(root,root_fd,source,value):
    """Bounded metadata-only resolution confined to no-follow project descriptors."""
    target=_target(root,source,value)
    seen={source}
    for _ in range(40):
        if target is _UNRESOLVED:return 'symlink_unresolved'
        if target is None:return 'symlink_external'
        parts=PurePosixPath(target).parts
        fd=os.dup(root_fd)
        restart=False
        try:
            for index,name in enumerate(parts):
                location='/'.join(parts[:index+1])
                entry=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISLNK(entry.st_mode):
                    if location in seen:return 'symlink_cyclic'
                    seen.add(location)
                    value=os.readlink(name,dir_fd=fd)
                    target=_target(root,location,value)
                    if target is not None and target is not _UNRESOLVED and index+1<len(parts):
                        target=posixpath.normpath(posixpath.join(target,*parts[index+1:]))
                    restart=True
                    break
                if index+1<len(parts):
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    os.close(fd);fd=child
            if not restart:return 'symlink_internal'
        except FileNotFoundError:return 'symlink_dangling'
        except OSError as error:
            return 'symlink_cyclic' if error.errno==errno.ELOOP else 'symlink_unresolved'
        finally:os.close(fd)
    return 'symlink_unresolved'


def scan(root):
    """Return (relative-path/bytes map, explicit completeness/exclusion evidence).

    POSIX no-follow directory descriptors pin the selected root once opened
    and prevent child directory/file replacements from following links. A platform lacking these primitives gets an honest partial
    result instead of a less safe fallback. Credential/runtime exclusions and the
    per-file byte budget remain intentional static scope, not completeness proof.
    """
    files={}
    metadata={'status':'complete_within_scope','executable_modes':{},'files_read':0,'excluded_count':0,'findings':[],
        'scope':'Permitted tracked and untracked working-tree regular text files; symlink targets are not read.',
        'limitations':['Read-only inventory only; snapshot/copy/repair/execution retain stricter validation.',
                       'Ignored directories count as one excluded entry; their descendants are not inspected.',
                       'Credential/runtime files, binary data and files over 1 MiB are outside static scope.',
                       'Symlink classification is bounded project-only metadata; absolute aliases outside the canonical root are conservatively external; unresolved targets are never read.']}
    def finding(source,operation,reason,error=None):
        row={'source':source or '.','operation':operation,'reason':reason,'state':'observed'}
        if error is not None:row['errno']=errno.errorcode.get(error.errno,'UNKNOWN')
        metadata['findings'].append(row);metadata['status']='partial';metadata['excluded_count']+=1
    if not all(hasattr(os,name) for name in ('O_DIRECTORY','O_NOFOLLOW')) or os.name!='posix':
        finding('.','list','safe_descriptor_scan_unavailable');return files,metadata
    try:
        root=Path(root).resolve()
        root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    except OSError as error:
        finding('.','list','access_error',error);return files,metadata

    def visit(fd,parent,depth):
        if depth>64:
            finding(parent.as_posix(),'list','directory_depth_budget');return
        try:
            with os.scandir(fd) as entries:names=sorted(entry.name for entry in entries)
        except OSError as error:
            finding(parent.as_posix(),'list','access_error',error);return
        for name in names:
            source=(parent/name).as_posix()
            try:entry=os.stat(name,dir_fd=fd,follow_symlinks=False)
            except OSError as error:
                finding(source,'stat','access_error',error);continue
            if stat.S_ISLNK(entry.st_mode):
                try:kind=_link_kind(root,root_fd,source,os.readlink(name,dir_fd=fd))
                except OSError as error:
                    finding(source,'readlink','access_error',error);continue
                finding(source,'exclude',kind);continue
            if _excluded(name,parent):
                metadata['excluded_count']+=1;continue
            if stat.S_ISDIR(entry.st_mode):
                try:child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                except OSError as error:
                    finding(source,'list','access_error',error);continue
                try:visit(child,parent/name,depth+1)
                finally:os.close(child)
                continue
            if not stat.S_ISREG(entry.st_mode):
                finding(source,'exclude','nonregular_input');continue
            if entry.st_size>_MAX:
                metadata['excluded_count']+=1;continue
            try:
                child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                try:
                    current=os.fstat(child)
                    if not stat.S_ISREG(current.st_mode):
                        finding(source,'read','input_changed');continue
                    with os.fdopen(child,'rb',closefd=False) as stream:raw=stream.read(_MAX+1)
                finally:os.close(child)
            except OSError as error:
                finding(source,'read','access_error',error);continue
            if len(raw)>_MAX or b'\0' in raw:
                metadata['excluded_count']+=1;continue
            files[source]=raw
            metadata['executable_modes'][source]=current.st_mode & 0o111
    try:visit(root_fd,PurePosixPath('.'),0)
    finally:os.close(root_fd)
    metadata['files_read']=len(files)
    return files,metadata
