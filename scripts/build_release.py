#!/usr/bin/env python3
"""Build a deterministic installable skill ZIP and external integrity metadata."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import zipfile

spec = importlib.util.spec_from_file_location('publication_policy', Path(__file__).with_name('check_publication.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
VERSION = re.compile(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][A-Za-z0-9-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][A-Za-z0-9-]*))*))?(?:\+([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*))?')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def build_release(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if (root / 'VERSION').is_symlink():
        raise ValueError('VERSION symlink refused')
    raw_version = (root / 'VERSION').read_text().strip()
    if not VERSION.fullmatch(raw_version):
        raise ValueError('VERSION must contain a valid SemVer version')
    entries = list((root / 'skills').glob('*/SKILL.md'))
    manifest_path = root / 'release.json'
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        name = manifest.get('skill')
        if not isinstance(name, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', name):
            raise ValueError('release.json skill must be a portable skill name')
        skill = root / 'skills' / name
        if not (skill / 'SKILL.md').is_file():
            raise ValueError('release.json selects a missing skill')
    else:
        if len(entries) != 1:
            raise ValueError('expected one skills/*/SKILL.md or release.json selection')
        skill = entries[0].parent
        name = skill.name
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', name):
        raise ValueError('invalid skill directory name')
    if output == root or root in output.parents:
        # Only the established ignored distribution directory may be inside source.
        if output != root / 'dist':
            raise ValueError('output must be external to source or the root dist directory')
    if skill.is_symlink() or (root / 'skills').is_symlink():
        raise ValueError('skill root symlink refused')
    license_path = root / 'LICENSE'
    if not license_path.is_file() or license_path.is_symlink():
        raise ValueError('regular root LICENSE required')
    payload = {name + '/LICENSE': license_path.read_bytes()}
    for path in sorted(skill.rglob('*')):
        relative = path.relative_to(skill)
        if path.is_symlink():
            raise ValueError('symlink refused in skill source')
        if path.is_dir():
            continue
        if '__pycache__' in relative.parts or path.suffix in {'.pyc', '.pyo'}:
            continue
        source_name = path.relative_to(root).as_posix()
        if not policy.allowed_path(source_name):
            raise ValueError('unexpected file in skill source: ' + relative.as_posix())
        data = path.read_bytes()
        if relative.as_posix() == 'LICENSE' and data != payload[name + '/LICENSE']:
            raise ValueError('skill LICENSE must match root LICENSE')
        findings = policy.content_findings(source_name, data)
        if findings:
            raise ValueError(relative.as_posix() + ': ' + ', '.join(findings))
        payload[name + '/' + relative.as_posix()] = data
    header = payload[name + '/SKILL.md'].decode('utf-8')
    if not re.search(r'^name:\s*' + re.escape(name) + r'\s*$', header, re.M):
        raise ValueError('SKILL.md name must match skill directory')
    findings = policy.content_findings('LICENSE', payload[name + '/LICENSE'])
    if findings:
        raise ValueError('LICENSE: ' + ', '.join(findings))
    revision = None
    try:
        if Path(policy.git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve() == root:
            revision = policy.git(root, 'rev-parse', 'HEAD').decode().strip()
    except subprocess.CalledProcessError:
        pass
    metadata = {'skill': name, 'version': raw_version, 'license': name + '/LICENSE',
                'source_revision': revision, 'source_revision_note': 'Informational HEAD only; archive hashes describe the packaged working tree.',
                'files': [{'path': key, 'sha256': digest(value), 'size': len(value)} for key, value in sorted(payload.items())]}
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + '-' + raw_version + '.zip')
    manifest = output / (name + '-' + raw_version + '.manifest.json')
    checksums = output / 'SHA256SUMS'
    if any(p.is_symlink() for p in (archive, manifest, checksums)):
        raise ValueError('output symlink refused')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as target:
        for key, value in sorted(payload.items()):
            info = zipfile.ZipInfo(key, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            target.writestr(info, value)
    manifest.write_text(json.dumps(metadata, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    checksums.write_text(''.join(digest(p.read_bytes()) + '  ' + p.name + '\n' for p in (archive, manifest)), encoding='ascii')
    return {'archive': archive, 'manifest': manifest, 'checksums': checksums}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_release(args.root, args.output)
    except (ValueError, OSError, KeyError) as exc:
        parser.exit(1, 'Release refused: ' + str(exc) + '\n')
    for path in result.values():
        print(path.name)


if __name__ == '__main__':
    main()
