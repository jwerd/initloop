import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from initloop.cli import main
from initloop.core import Run

class NativeCLITests(unittest.TestCase):
    def test_native_baseline_and_verification_require_no_image_or_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'project';root.mkdir();(root/'app.py').write_text("print('working')\n")
            subprocess.run(['git','init','-q',str(root)],check=True)
            subprocess.run(['git','-C',str(root),'add','.'],check=True)
            from initloop.stack import discover
            decision=discover(root)['runner_decision']
            self.assertEqual(decision['status'],'choice_required')
            self.assertEqual({o['kind'] for o in decision['options']},{'native','compose'})
            # Simulated authorized choice selects native; then exercise the actual CLI.
            run=Run.create(root,Path(tmp)/'runs',{'objective':'print working','checks':[{'name':'output','source':'independent contract','argv':[sys.executable,'app.py'],'contains':['working']}]})
            with patch('initloop.cli.DockerBackend',side_effect=AssertionError('native must not require Docker')),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['baseline',str(run.root),'--runner','native']),0)
                run=Run(run.root);run.patch({'README.md':'Native workflow'})
                self.assertEqual(main(['verify',str(run.root),'--runner','native']),0)
            report=json.loads((run.root/'verification.json').read_text())
            self.assertEqual(len(report),2)
            self.assertTrue(all(r['passed'] and r['runner']=='native' and not r['sandboxed'] for r in report))
