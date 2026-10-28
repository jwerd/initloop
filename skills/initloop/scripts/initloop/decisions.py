"""Persistent dependency planning only; never executes or applies setup.

Catalogs/findings are supplied by the invoking harness from inspected evidence.
They are not runtime certification or protection against a hostile controller.
"""
import copy
import json
import textwrap
from pathlib import Path

from .core import write_json
from .workflow import audit


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _catalog(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError('nonempty dependency catalog required')
    names = set()
    for row in rows:
        if not isinstance(row, dict) or not all(_text(row.get(k)) for k in ('id', 'label')):
            raise ValueError('dependency id and label required')
        if row['id'] in names:
            raise ValueError('duplicate dependency id')
        names.add(row['id'])
        options = row.get('options')
        if not isinstance(options, list) or not options:
            raise ValueError('dependency options required')
        ids = set()
        for option in options:
            if not isinstance(option, dict) or not all(_text(option.get(k)) for k in
                    ('id', 'label', 'impact', 'access', 'unsupported', 'verification')):
                raise ValueError('option requires id, label, impact, access, unsupported and verification')
            if option['id'] in ids:
                raise ValueError('duplicate option id')
            if 'blocked' in option and not _text(option['blocked']):
                raise ValueError('blocked option requires a reason')
            ids.add(option['id'])
            if not isinstance(option.get('evidence'), list) or not option['evidence'] or not all(map(_text, option['evidence'])):
                raise ValueError('option evidence required; unsupported capabilities must not be offered')
        if not _text(row.get('suggested')) or row['suggested'] not in ids:
            raise ValueError('suggested option must exist')
        if not isinstance(row.get('evidence'), list) or not row['evidence'] or not all(map(_text, row['evidence'])):
            raise ValueError('dependency evidence required')


class Checkpoint:
    """One private external controller directory per decision session.

    Sequential single-controller writes; stale instances refuse to overwrite.
    No apply operation: review returns a plan for separately authorized setup.
    """
    @classmethod
    def create(cls, project, directory, catalog):
        project = Path(project).resolve(strict=True)
        directory = Path(directory).resolve()
        if not project.is_dir() or project == directory or project in directory.parents or directory in project.parents:
            raise ValueError('decision state must be outside source and its ancestors')
        if directory.exists():
            raise ValueError('decision directory already exists; resume it instead')
        _catalog(catalog)
        report = audit(project)
        rows = [{k: copy.deepcopy(row[k]) for k in ('id', 'label', 'evidence', 'options', 'suggested')}
                for row in catalog]
        for row in rows:
            row.update(status='suggested', selected=None, findings=[], blockers=[])
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        write_json(directory / 'decisions.json', {
            'schema': 1, 'project': str(project), 'snapshot_digest': report['snapshot_digest'],
            'discovery_scan': report['discovery_scan'], 'phase': 'overview',
            'investigating': [], 'dependencies': rows, 'events': [], 'applied': False})
        return cls(directory)

    def __init__(self, directory):
        self.directory = Path(directory).resolve(strict=True)
        self.path = self.directory / 'decisions.json'
        if self.path.is_symlink():
            raise ValueError('decision state cannot be a symlink')
        self.state = json.loads(self.path.read_text())
        if not isinstance(self.state, dict) or self.state.get('schema') != 1:
            raise ValueError('unsupported decision state')
        _catalog(self.state.get('dependencies'))
        self._saved = copy.deepcopy(self.state)

    def _row(self, name, state=None):
        for row in (state if state is not None else self.state)['dependencies']:
            if row['id'] == name:
                return row
        raise ValueError('unknown dependency: ' + name)

    def _change(self, action, operation, allow_cancelled=False):
        if self.state['phase'] == 'cancelled' and not allow_cancelled:
            raise ValueError('resume the cancelled checkpoint first')
        if self.path.is_symlink() or json.loads(self.path.read_text()) != self._saved:
            raise ValueError('decision state changed; reload before continuing')
        state = copy.deepcopy(self.state)
        operation(state)
        state['events'].append({'action': action})
        write_json(self.path, state)
        self.state = state
        self._saved = copy.deepcopy(state)
        return copy.deepcopy(state)

    def investigate(self, names):
        if not names or len(set(names)) != len(names):
            raise ValueError('choose one or more distinct dependencies')
        for name in names:
            self._row(name)
        def update(state):
            state.update(phase='investigation', investigating=list(names))
        return self._change('investigate', update)

    def findings(self, name, text, affected=()):
        self._row(name)
        if not _text(text):
            raise ValueError('finding text required; record facts and citations, never secrets')
        for other in affected:
            self._row(other)
        def update(state):
            self._row(name, state)['findings'].append(text)
            for other in affected:
                row = self._row(other, state)
                row['status'] = 'blocked'
                row['blockers'].append({'from': name, 'finding': text})
            # Any changed evidence invalidates the combined review.
            state.update(phase='overview', investigating=[])
        return self._change('findings', update)

    def select(self, name, option):
        row = self._row(name)
        selected = next((o for o in row['options'] if o['id'] == option), None)
        if selected is None:
            raise ValueError('unknown or unsupported option: ' + str(option))
        if selected.get('blocked'):
            raise ValueError('option blocked: ' + selected['blocked'])
        def update(state):
            row = self._row(name, state)
            row.update(selected=option, status='selected', blockers=[])
            state.update(phase='overview', investigating=[])
        return self._change('select:' + name + ':' + option, update)

    def revise(self, catalog):
        """Replace evidence/options after harness reinspection, preserving decisions.

        Stable dependency IDs are required. Changed selected options are blocked
        until explicit reselection; unrelated choices and all findings survive.
        """
        _catalog(catalog)
        if {r['id'] for r in catalog} != {r['id'] for r in self.state['dependencies']}:
            raise ValueError('revision requires the same dependency IDs; start a fresh checkpoint for scope changes')
        current = audit(Path(self.state['project']))
        drift = (current['snapshot_digest'] != self.state['snapshot_digest'] or
                 current['discovery_scan'] != self.state['discovery_scan'])
        def update(state):
            for new in catalog:
                row = self._row(new['id'], state)
                old_option = next((o for o in row['options'] if o['id'] == row['selected']), None)
                new_option = next((o for o in new['options'] if o['id'] == row['selected']), None)
                changed = old_option != new_option or row['evidence'] != new['evidence']
                for key in ('label', 'evidence', 'options', 'suggested'):
                    row[key] = copy.deepcopy(new[key])
                if drift or (row['selected'] is not None and changed):
                    row['status'] = 'blocked'
                    row['blockers'].append({'from': 'catalog', 'finding': 'Reinspected source or selected capability changed; explicitly reconfirm a supported choice'})
            state.update(phase='overview', investigating=[], snapshot_digest=current['snapshot_digest'],
                         discovery_scan=current['discovery_scan'])
        return self._change('revise-catalog', update)

    def review(self):
        # Inventory equality detects included source drift, not provider/harness changes.
        current = audit(Path(self.state['project']))
        if (current['snapshot_digest'] != self.state['snapshot_digest'] or
                current['discovery_scan'] != self.state['discovery_scan']):
            def invalidate(state):
                for row in state['dependencies']:
                    row['status'] = 'blocked'
                    row['blockers'].append({'from': 'source', 'finding': 'Source discovery changed; revise the catalog after reinspection'})
                state.update(phase='overview', investigating=[])
            self._change('source-changed', invalidate)
            raise ValueError('source discovery changed; re-inspect and revise the catalog; choices retained')
        unresolved = [r['id'] for r in self.state['dependencies'] if r['status'] != 'selected']
        if unresolved:
            raise ValueError('unresolved decisions: ' + ', '.join(unresolved))
        def update(state):
            state.update(phase='review', investigating=[])
        return self._change('review', update)

    def back(self):
        def update(state):
            state.update(phase='overview', investigating=[])
        return self._change('back', update)

    def cancel(self):
        def update(state):
            state.update(phase='cancelled', investigating=[])
        return self._change('cancel', update)

    def resume(self):
        def update(state):
            state.update(phase='overview', investigating=[])
        return self._change('resume', update, allow_cancelled=True)


def overview(state):
    lines = ['Dependency checkpoint — ' + state['phase'], 'Planning only. No setup has been applied.']
    for index, row in enumerate(state['dependencies'], 1):
        lines.append('{}: {} [{}] selected={} suggested={}'.format(
            index, row['label'], row['status'], row['selected'] or '—', row['suggested']))
        for finding in row['findings']:
            lines.append('   Finding: ' + finding)
        for blocker in row['blockers']:
            lines.append('   BLOCKED: ' + blocker['from'] + ': ' + blocker['finding'])
    return '\n'.join(lines)


def describe(option):
    lines = [option['label'] + (' [BLOCKED: ' + option['blocked'] + ']' if option.get('blocked') else '')]
    for key in ('evidence', 'impact', 'access', 'unsupported', 'verification'):
        value = '; '.join(option[key]) if key == 'evidence' else option[key]
        lines.extend(textwrap.wrap(key.title() + ': ' + value, width=76,
                                   initial_indent='   ', subsequent_indent='   '))
    return '\n'.join(lines)


def interactive(checkpoint, read=input, write=print, investigate=None):
    """Numbered fallback. The skill uses the host picker when available.

    This deterministic controller neither investigates code nor interprets prose;
    harnesses supply evidence with the findings operation outside this fallback.
    """
    cp = checkpoint
    while True:
        write(overview(cp.state))
        write('Enter dependency numbers (e.g. 1,2) to investigate/revisit; review, back, cancel, resume, or quit.')
        try:
            answer = read('checkpoint> ').strip().lower()
            if answer == 'quit':
                return
            if answer in {'review', 'back', 'cancel', 'resume'}:
                getattr(cp, answer)()
                if answer == 'review':
                    write('Combined plan — inspect every selected impact/access/limit before separate setup authorization:')
                    for row in cp.state['dependencies']:
                        write(row['label'] + ': ' + describe(next(o for o in row['options'] if o['id'] == row['selected'])))
                    write('Back revisits choices; cancel retains them. This helper has no apply operation.')
                continue
            names = [cp.state['dependencies'][int(n.strip()) - 1]['id'] for n in answer.split(',')
                     if n.strip().isdigit() and 1 <= int(n.strip()) <= len(cp.state['dependencies'])]
            if len(names) != len(answer.split(',')):
                raise ValueError('use listed dependency numbers or commands')
            cp.investigate(names)
            for name in names:
                if investigate is not None:
                    if investigate(cp, name, read, write) is False:
                        break
                row = cp._row(name)
                write(row['label'] + ' evidence: ' + '; '.join(row['evidence']))
                for finding in row['findings']:
                    write('Finding: ' + finding)
                for index, option in enumerate(row['options'], 1):
                    write(str(index) + ': ' + describe(option))
                write('Choose an option number explicitly, or back to keep current choices.')
                choice = read(name + '> ').strip().lower()
                if choice == 'back':
                    break
                if not choice.isdigit() or not 1 <= int(choice) <= len(row['options']):
                    raise ValueError('use a listed option number or back')
                cp.select(name, row['options'][int(choice) - 1]['id'])
            cp.back()
        except (EOFError, KeyboardInterrupt):
            write('\nSession retained; run again to continue. No setup applied.')
            return
        except ValueError as error:
            write(str(error))
