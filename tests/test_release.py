"""Release guarantees using isolated synthetic source trees."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'source'
        self.skill = self.root / 'skills' / 'sample-skill'
        (self.skill / 'scripts').mkdir(parents=True)
        (self.skill / 'references').mkdir()
        (self.root / 'VERSION').write_text('0.1.0-alpha.3\n')
        (self.root / 'LICENSE').write_text('Synthetic test license\n')
        (self.skill / 'SKILL.md').write_text('---\nname: sample-skill\ndescription: Example\n---\nPortable example.\n')
        (self.skill / 'scripts' / 'tool.py').write_text('print("example")\n')
        (self.skill / 'references' / 'guide.md').write_text('Example guide\n')
        self.builder = load('build_release')
        self.checker = load('check_publication')

    def test_readme_artwork_allowlist_is_exact_and_scanned(self):
        for name in ('initloop-loop.svg', 'initloop-logo.svg'):
            path = 'assets/' + name
            self.assertTrue(self.checker.allowed_path(path))
            self.assertEqual(self.checker.content_findings(path, b'<svg/>'), [])
            self.assertTrue(self.checker.content_findings(path, b'<svg>/Users/' + b'example/private</svg>'))
        for path in ('assets/other.svg', 'assets/key.txt', 'assets/nested/initloop-logo.svg'):
            self.assertFalse(self.checker.allowed_path(path))

    def build(self, name='out'):
        return self.builder.build_release(self.root, Path(self.tmp.name) / name)

    def test_reproducible_license_manifest_and_hashes(self):
        first, second = self.build('one'), self.build('two')
        self.assertEqual(first['archive'].read_bytes(), second['archive'].read_bytes())
        self.assertEqual(first['manifest'].read_bytes(), second['manifest'].read_bytes())
        with zipfile.ZipFile(first['archive']) as archive:
            self.assertEqual(archive.read('sample-skill/LICENSE'), (self.root / 'LICENSE').read_bytes())
            manifest = json.loads(first['manifest'].read_text())
            self.assertEqual(manifest['version'], '0.1.0-alpha.3')
            self.assertEqual(set(archive.namelist()), {item['path'] for item in manifest['files']})
            for item in manifest['files']:
                self.assertEqual(item['sha256'], hashlib.sha256(archive.read(item['path'])).hexdigest())
                self.assertEqual(archive.getinfo(item['path']).date_time, (1980, 1, 1, 0, 0, 0))
        sums = first['checksums'].read_text()
        for key in ('archive', 'manifest'):
            self.assertIn(hashlib.sha256(first[key].read_bytes()).hexdigest() + '  ' + first[key].name, sums)
        self.assertNotIn(str(self.root), first['manifest'].read_text())

    def test_runtime_files_are_excluded(self):
        (self.skill / '__pycache__').mkdir()
        (self.skill / '__pycache__' / 'tool.pyc').write_bytes(b'cache')
        self.build()
        with zipfile.ZipFile(self.build('second')['archive']) as archive:
            self.assertFalse(any('__pycache__' in item for item in archive.namelist()))

    def test_unknown_file_and_environment_file_refused(self):
        for name in ('private.json', '.env'):
            with self.subTest(name=name):
                path = self.skill / name
                path.write_text('synthetic')
                with self.assertRaises(ValueError):
                    self.build()
                path.unlink()

    def test_symlink_refused(self):
        (self.skill / 'scripts' / 'linked.py').symlink_to(self.skill / 'scripts' / 'tool.py')
        with self.assertRaises(ValueError):
            self.build()

    def test_invalid_version_refused(self):
        for value in ('../escape', 'v1.0', '01.0.0', '1.0.0-alpha.01', '1.0.0\nextra'):
            (self.root / 'VERSION').write_text(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.build()

    def test_private_content_refused_without_disclosing_value(self):
        secret = 'sk-' + 'syntheticprivatecredential0123456789'
        (self.skill / 'references' / 'guide.md').write_text(secret)
        with self.assertRaises(ValueError) as caught:
            self.build()
        self.assertNotIn(secret, str(caught.exception))

    def test_publication_detects_staged_ignored_file_and_private_path(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        (self.root / '.gitignore').write_text('.env\n')
        (self.root / '.env').write_text('SYNTHETIC=value')
        subprocess.run(['git', '-C', str(self.root), 'add', '-f', '.env'], check=True)
        self.assertTrue(self.checker.check_publication(self.root))
        (self.root / '.env').unlink()
        subprocess.run(['git', '-C', str(self.root), 'rm', '--cached', '-q', '.env'], check=True)
        (self.skill / 'references' / 'guide.md').write_text('/' + 'Users/' + 'synthetic-person/private')
        self.assertTrue(self.checker.check_publication(self.root))

    def test_publication_accepts_clean_source(self):
        (self.root / 'tests').mkdir()
        (self.root / 'tests' / 'test_synthetic.py').write_text(
            'password = ' + '"' + 'syntheticcredential' + '"')
        self.assertEqual(self.checker.check_publication(self.root), [])

    def test_staged_content_is_checked_even_if_working_file_is_clean(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        guide = self.skill / 'references' / 'guide.md'
        guide.write_text('sk-' + 'syntheticprivatecredential0123456789')
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        guide.write_text('Clean working content')
        self.assertTrue(any('staged' in item for item in self.checker.check_publication(self.root)))

    def test_deleted_historical_private_content_is_checked(self):
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        guide = self.skill / 'references' / 'guide.md'
        guide.write_text('sk-' + 'syntheticprivatecredential0123456789')
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.root), '-c', 'user.name=Synthetic Test',
                        '-c', 'user.email=synthetic@example.invalid', 'commit', '-qm', 'Synthetic fixture'], check=True)
        guide.write_text('Clean working content')
        subprocess.run(['git', '-C', str(self.root), 'add', '.'], check=True)
        self.assertEqual(self.checker.check_publication(self.root), [])
        self.assertTrue(any('history' in item for item in self.checker.check_publication(self.root, history=True)))

    def test_output_inside_skill_refused(self):
        with self.assertRaises(ValueError):
            self.builder.build_release(self.root, self.skill / 'output')


if __name__ == '__main__':
    unittest.main()
