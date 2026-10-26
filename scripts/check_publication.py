#!/usr/bin/env python3
"""Conservative public-source allowlist and heuristic privacy checks.

This is an accidental-disclosure guard, not a proof that source has no secrets.
Findings identify paths and categories, never matching secret values.
"""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess

ROOT_FILES = {'README.md', 'LICENSE', 'VERSION', '.gitignore', 'release.json', 'CHANGELOG.md', 'CONTRIBUTING.md', 'PROVENANCE.md', 'SECURITY.md'}
ROOT_SCRIPTS = {'check_skill.py', 'build_release.py', 'check_publication.py'}
PRIVATE = re.compile(r'/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\|dispatch[-_ ]receipt|\b(?:thread|task)[_-]id\s*[:=]', re.I)
CREDENTIAL = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bsk-[A-Za-z0-9_-]{20,}|\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}|\bAKIA[A-Z0-9]{16}\b|\b(?:password|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*[\"\x27]?[A-Za-z0-9/+_=-]{12,}', re.I)


def allowed_path(name):
    parts = PurePosixPath(name).parts
    if not parts or any(p in {'.', '..'} for p in parts):
        return False
    if len(parts) == 1:
        return name in ROOT_FILES
    if parts[0] == 'scripts':
        return len(parts) == 2 and parts[1] in ROOT_SCRIPTS
    if parts[0] == 'tests':
        return len(parts) == 2 and parts[1].startswith('test_') and parts[1].endswith('.py')
    if parts[0] == '.github':
        return len(parts) == 3 and parts[1] == 'workflows' and parts[2].endswith(('.yml', '.yaml'))
    if parts[0] == 'skills' and len(parts) >= 3:
        sub = parts[2:]
        return (sub in {('SKILL.md',), ('LICENSE',)} or
                (sub[0] == 'scripts' and len(sub) >= 2 and sub[-1].endswith('.py')) or
                (sub[0] in {'references', 'refs'} and len(sub) >= 2 and sub[-1].endswith('.md')) or
                sub == ('agents', 'openai.yaml')) and not any(p.startswith('.') or p == '__pycache__' for p in sub)
    return False


def content_findings(name, data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return ['non-UTF-8 content']
    findings = []
    # Tests intentionally exercise credential filters using synthetic values.
    # Host paths and receipts are forbidden everywhere, including tests.
    if PRIVATE.search(text):
        findings.append('private host path or internal receipt identifier')
    credential_pattern = CREDENTIAL
    if name.startswith('tests/'):
        text = text.replace('sk-proj-' + 'abcdefghijklmnop', 'SYNTHETIC_CREDENTIAL')
        credential_pattern = re.compile(CREDENTIAL.pattern.split(r'|\b(?:password')[0], re.I)
    if credential_pattern.search(text):
        findings.append('possible credential material')
    return findings


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout


def check_publication(root, history=False):
    root = Path(root).resolve()
    findings = []
    # A parent repository does not make this staging tree a publication repository.
    try:
        is_repo = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == root
    except subprocess.CalledProcessError:
        is_repo = False
    if is_repo:
        names = set(git(root, 'ls-files', '--cached', '--others', '--exclude-standard', '-z').decode().split('\0')) - {''}
    else:
        names = {p.relative_to(root).as_posix() for p in root.rglob('*')
                 if (p.is_file() or p.is_symlink()) and not any(x in {'.git', '__pycache__', 'dist', 'build'} for x in p.relative_to(root).parts)}
    for name in sorted(names):
        path = root / name
        if not allowed_path(name):
            findings.append(name + ': outside public source allowlist')
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != root and root in p.parents):
            findings.append(name + ': symlink refused')
        elif path.exists():
            findings.extend(name + ': ' + finding for finding in content_findings(name, path.read_bytes()))
    if is_repo:
        # The index may differ from the working tree; publication must check both.
        for record in filter(None, git(root, 'ls-files', '--stage', '-z').split(b'\0')):
            meta, raw_name = record.split(b'\t', 1)
            mode, oid, stage = meta.decode().split()
            name = raw_name.decode('utf-8', errors='replace')
            if stage != '0' or mode not in {'100644', '100755'}:
                findings.append(name + ': staged symlink or nonregular/unmerged entry refused')
            elif mode in {'100644', '100755'}:
                findings.extend(name + ': staged ' + item for item in content_findings(name, git(root, 'cat-file', 'blob', oid)))
    if history:
        if not is_repo:
            findings.append('history: repository required')
        else:
            # Walk each committed tree, including deleted content and old paths.
            # Report revision/category only; historical paths may themselves be private.
            for revision in git(root, 'rev-list', '--all').decode().splitlines():
                records = git(root, 'ls-tree', '-r', '-z', revision).split(b'\0')
                for record in filter(None, records):
                    meta, raw_name = record.split(b'\t', 1)
                    mode, kind, oid = meta.decode().split()
                    name = raw_name.decode('utf-8', errors='replace')
                    prefix = 'history ' + revision[:12] + ': '
                    if mode == '120000' or kind != 'blob' or not allowed_path(name):
                        findings.append(prefix + 'disallowed historical entry')
                    if kind == 'blob':
                        findings.extend(prefix + item for item in content_findings(name, git(root, 'cat-file', 'blob', oid)))
    return sorted(set(findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--history', action='store_true', help='also inspect all reachable committed trees/blobs')
    args = parser.parse_args()
    findings = check_publication(args.root, args.history)
    for finding in findings:
        print(finding)
    if not findings:
        print('PASS: public source allowlist and heuristic privacy checks')
    return bool(findings)


if __name__ == '__main__':
    raise SystemExit(main())
