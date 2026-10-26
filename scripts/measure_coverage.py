#!/usr/bin/env python3
"""Dev-only coverage runner, including helper supervisors in isolated Python startup.

Install coverage==7.10.7 in a development environment, then invoke this script
with that environment's Python. Neither coverage nor the startup hook ships in
the skill. Output and instrumentation remain outside the source checkout.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


def measured_digest(root, runtime):
    """Bind coverage to its runtime/tests and refuse a concurrent-source run."""
    digest = hashlib.sha256()
    paths = list(runtime.rglob('*.py')) + list((root / 'tests').glob('test_*.py'))
    for path in sorted(paths):
        name = path.relative_to(root).as_posix().encode()
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, 'big') + name)
        digest.update((path.stat().st_mode & 0o777).to_bytes(4, 'big'))
        digest.update(len(content).to_bytes(8, 'big') + content)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pattern', default='test_*.py')
    parser.add_argument('--require-supervisors', action='store_true',
                        help='fail if no lifecycle supervisor entrypoint was measured (automatic for the full suite)')
    parser.add_argument('--min-statements', type=float, default=89)
    parser.add_argument('--min-branches', type=float, default=75)
    args = parser.parse_args(argv)
    require_supervisors = args.require_supervisors or args.pattern == 'test_*.py'
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output == root or root in output.parents:
        parser.error('--output must be outside the source checkout')
    if output.exists() and any(output.iterdir()):
        parser.error('--output must be empty or absent; prior evidence is never overwritten')
    try:
        import coverage
    except ImportError:
        parser.error('development dependency missing: install coverage==7.10.7 into an isolated venv')
    output.mkdir(parents=True, exist_ok=True)
    config = output / 'coverage.ini'
    runtime = root / 'skills' / 'initloop' / 'scripts' / 'initloop'
    before = measured_digest(root, runtime)
    config.write_text('[run]\nbranch = true\nparallel = true\nsigterm = true\n'
                      'source = ' + str(runtime) + '\ndata_file = ' + str(output / '.coverage') + '\n')
    with tempfile.TemporaryDirectory(prefix='initloop-coverage-') as temporary:
        isolated = Path(temporary) / 'python'
        venv.EnvBuilder(with_pip=False, symlinks=os.name != 'nt').create(isolated)
        python = isolated / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        site = subprocess.check_output([str(python), '-c', 'import site; print(site.getsitepackages()[0])'], text=True).strip()
        # The lifecycle supervisor deliberately drops ambient environment values.
        # An isolated interpreter hook starts coverage before every Python child,
        # without weakening that runtime policy or touching installed user hooks.
        hook = Path(site) / 'initloop_measurement.pth'
        hook.write_text(str(Path(coverage.__file__).resolve().parent.parent) + '\n'
                        'import os; os.environ["COVERAGE_PROCESS_START"] = ' + repr(str(config)) +
                        '; import coverage; coverage.process_startup()\n')
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        env['PYTHONPATH'] = str(root / 'skills' / 'initloop' / 'scripts')
        completed = subprocess.run([str(python), '-m', 'unittest', 'discover', '-s', str(root / 'tests'),
                                    '-p', args.pattern, '-v'], cwd=root, env=env)
    after = measured_digest(root, runtime)
    process_files = list(output.glob('.coverage.*'))
    lifecycle = runtime / 'lifecycle.py'
    entrypoint_lines = {node.lineno for node in ast.walk(ast.parse(lifecycle.read_text()))
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'serve'}
    supervisor_processes = 0
    for data_file in process_files:
        data = coverage.CoverageData(basename=str(data_file))
        data.read()
        if entrypoint_lines.intersection(data.lines(str(lifecycle)) or []):
            supervisor_processes += 1
    cov = coverage.Coverage(config_file=str(config))
    cov.combine(strict=True, keep=True)
    cov.save()
    cov.json_report(outfile=str(output / 'coverage.json'))
    cov.xml_report(outfile=str(output / 'coverage.xml'))
    cov.report(file=sys.stdout, show_missing=True)
    report = json.loads((output / 'coverage.json').read_text())
    totals = report['totals']
    statements = 100 * totals['covered_lines'] / max(1, totals['num_statements'])
    branches = 100 * totals['covered_branches'] / max(1, totals['num_branches'])
    modules = {}
    for name, item in report['files'].items():
        counts = item['summary']
        modules[Path(name).name] = {
            'statement_percent': round(100 * counts['covered_lines'] / counts['num_statements'], 2) if counts['num_statements'] else 100,
            'branch_percent': round(100 * counts['covered_branches'] / counts['num_branches'], 2) if counts['num_branches'] else 100,
        }
    summary = {'statement_percent': round(statements, 2), 'branch_percent': round(branches, 2),
               'statement_gate': args.min_statements, 'branch_gate': args.min_branches,
               'test_exit_code': completed.returncode, 'scope': 'distributed runtime package; launcher and packaging excluded',
               'subprocesses': 'isolated interpreter startup hook includes Python supervisors; SIGKILL cannot flush coverage',
               'docker_image': os.environ.get('INITLOOP_DOCKER_IMAGE'),
               'coverage_version': coverage.__version__, 'python_process_data_files': len(process_files),
               'supervisor_entrypoint_process_files': supervisor_processes, 'modules': modules,
               'measured_input_sha256_before': before, 'measured_input_sha256_after': after,
               'source_changed_during_measurement': before != after,
               'supervisor_collection_required': require_supervisors}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    failed = (completed.returncode or before != after or statements < args.min_statements
              or branches < args.min_branches or (require_supervisors and not supervisor_processes))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
