#!/usr/bin/env python3
"""Interactive synthetic decision fixture, backed by the shipped checkpoint.

No app code is executed, no LDAP/mail/API server is started, no host picker or
live-agent investigation is simulated as real. All fixture facts are declared.
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from initloop.decisions import Checkpoint, interactive


def catalog():
    rows = []
    for name, label, local, impact, unsupported in [
        ('ldap', 'LDAP login', 'Local LDAP / synthetic identities',
         'Separate local LDAP configuration exercises the existing LDAP path; no authentication source edits.',
         'Corporate schemas, policies, TLS, group mapping and actual corporate compatibility are unverified.'),
        ('email', 'Email delivery', 'Local mail capture',
         'Isolated SMTP endpoint captures messages locally; no delivery to real recipients.',
         'Real provider delivery, reputation and provider-specific behavior are unverified.'),
        ('reporting', 'Reporting API', 'Local contract fixture',
         'Separate endpoint override uses synthetic report responses from the fixture contract.',
         'Real provider auth, complete data and undocumented semantics are unverified.')]:
        evidence = ['SYNTHETIC fixture.md: ' + name + ' consumer supports endpoint configuration']
        rows.append({'id': name, 'label': label, 'evidence': evidence,
                     'suggested': 'local', 'options': [
                         {'id': 'local', 'label': local, 'evidence': evidence,
                          'impact': impact, 'access': 'Later approval for an isolated local service and supported config override; not started by this demo.',
                          'unsupported': unsupported, 'verification': 'Later run consumer success/failure probes; fixture planning verifies no integration.'},
                         {'id': 'corporate', 'label': 'Approved development integration', 'evidence': evidence,
                          'impact': 'Connect through supported configuration to an approved development provider.',
                          'access': 'Approved development endpoint, scoped credentials and network access.',
                          'unsupported': 'No approved provider supplied in this synthetic fixture.',
                          'verification': 'Later test actual integration with permission.',
                          'blocked': 'No approved development integration supplied; no corporate access is claimed.'}]})
    return rows


def investigate(cp, name, read, write):
    if name == 'ldap':
        write('SYNTHETIC LDAP investigation: existing LDAP endpoint configuration; no development-login capability evidenced. Authentication source must stay unchanged.')
        write('To test corporate integration, an approved development directory and network access are required.')
        write('Directory access: 1 Approved dev directory (not supplied here); 2 No approved dev directory; 3 I need something local; back')
        answer = read('directory> ').strip().lower()
        if answer in {'2', '3'}:
            cp.findings(name, 'SYNTHETIC: No approved dev directory. User needs something local. Local LDAP exercises LDAP paths with synthetic identities; corporate compatibility remains unverified.')
        elif answer == '1':
            cp.findings(name, 'SYNTHETIC: Corporate integration requested, but no approved dev endpoint/access supplied. Corporate option remains blocked; no connection attempted.')
        elif answer == 'back':
            return False
        else:
            raise ValueError('choose 1, 2, 3, or back; previous decisions retained')
    else:
        write('SYNTHETIC investigation: fixture contract only; no actual work app or provider inspected.')
        cp.findings(name, 'SYNTHETIC: Inspected declared fixture ' + name + ' configuration/contract. Local substitute is a proposal; provider verification is still required.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--session', type=Path, required=True, help='new or existing external demo directory')
    args = parser.parse_args()
    root = args.session.resolve()
    if not root.exists():
        root.mkdir(parents=True, mode=0o700)
        project = root / 'sample'
        project.mkdir()
        (project / 'fixture.md').write_text(
            '# SYNTHETIC decision-only fixture\n'
            'ldap consumer supports endpoint configuration; development login is absent.\n'
            'email consumer supports endpoint configuration (SMTP).\n'
            'reporting consumer supports endpoint configuration and a synthetic report contract.\n'
            'These are authored demo facts, not inspected app behavior. No executable app is bundled.\n')
        cp = Checkpoint.create(project, root / 'checkpoint', catalog())
    else:
        cp = Checkpoint(root / 'checkpoint')
    print('INITLOOP — SYNTHETIC INTERACTIVE CHECKPOINT DEMO')
    print('Actual checkpoint state machine; authored investigation prompts. No live agent, host picker, app integration, source edits or service setup.')
    print('Session:', root)
    print('Suggested route: 1 → directory 3 → option 1; inspect overview; 2,3 → option 1 each; revisit 1; review; back; cancel; resume; quit.')
    interactive(cp, investigate=investigate)


if __name__ == '__main__':
    main()
