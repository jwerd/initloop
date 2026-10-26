"""CI declarations are bounded static evidence, not executed recommendations."""
import json
import unittest
from initloop.ci_source import discover_ci


class CISourceTests(unittest.TestCase):
    def scan(self, workflow, files=None):
        return discover_ci({'.github/workflows/check.yml': workflow.encode(), **(files or {})})

    def observations(self, result, kind):
        return [row for flow in result['workflows'] for row in flow['observations'] if row['kind'] == kind]

    def test_nested_working_directory_build_script_version_and_services_are_cited(self):
        source = ('defaults:\n  run:\n    working-directory: services/odd\njobs:\n  verify:\n'
                  '    runs-on: ubuntu-latest\n    services:\n      store:\n        image: postgres:16\n'
                  '    steps:\n      - uses: actions/setup-python@v5\n        with:\n          python-version: "3.12"\n'
                  '      - run: |\n          python3 forge.py\n          python3 -m unittest discover\n')
        result = self.scan(source, {'services/odd/forge.py':b'pass'})
        commands = self.observations(result, 'command')
        self.assertEqual([(r['command'],r['cwd'],r['line']) for r in commands],
                         [('python script','services/odd',15),('python -m unittest','services/odd',16)])
        self.assertTrue(all(r['status']=='declared_unverified' and not r['runtime_verified'] for r in commands))
        self.assertEqual(self.observations(result,'script')[0]['target'],'services/odd/forge.py')
        self.assertTrue(self.observations(result,'script')[0]['exists'])
        self.assertEqual(self.observations(result,'runtime')[0]['version'],'3.12')
        self.assertEqual(self.observations(result,'service')[0]['image'],'postgres:16')

    def test_job_and_step_cwd_override_without_leaking_to_next_step(self):
        source = ('defaults:\n  run:\n    working-directory: rootdir\njobs:\n  check:\n'
                  '    defaults:\n      run:\n        working-directory: nested\n    steps:\n'
                  '      - run: python3 test.py\n        working-directory: other\n'
                  '      - run: python3 test.py\n  next:\n    steps:\n      - run: python3 test.py\n')
        rows=self.observations(self.scan(source),'command')
        self.assertEqual([r['cwd'] for r in rows],['other','nested','rootdir'])

    def test_dynamic_cwd_does_not_silently_inherit_static_default(self):
        source=('defaults:\n  run:\n    working-directory: known\njobs:\n  check:\n    steps:\n'
                '      - run: python3 build.py\n        working-directory: ${{ matrix.location }}\n')
        result=self.scan(source,{'known/build.py':b'pass'})
        self.assertIsNone(self.observations(result,'command')[0]['cwd'])
        self.assertEqual(self.observations(result,'script'),[])
        self.assertTrue(result['unknowns'])

    def test_missing_script_artifact_and_dynamic_references_stay_uncertain(self):
        source=('jobs:\n  check:\n    steps:\n      - run: python3 gone.py\n'
                '      - uses: actions/upload-artifact@v4\n        with:\n          path: output/report.json\n'
                '      - uses: actions/setup-python@v5\n        with:\n          python-version: ${{ matrix.python }}\n')
        result=self.scan(source)
        self.assertFalse(self.observations(result,'script')[0]['exists'])
        self.assertFalse(self.observations(result,'artifact')[0]['exists'])
        self.assertEqual(self.observations(result,'runtime'),[])
        self.assertGreaterEqual(len(result['unknowns']),3)

    def test_production_cues_are_not_local_execution_authorization(self):
        source=('jobs:\n  release:\n    environment: production\n    steps:\n'
                '      - run: npm run deploy\n      - run: python3 verify.py\n')
        result=self.scan(source)
        self.assertTrue(all(r['local_appropriateness']=='production_only' for r in self.observations(result,'command')))
        self.assertFalse(any(r['runtime_verified'] for r in self.observations(result,'command')))

    def test_inert_arbitrary_commands_env_values_and_names_are_not_reported(self):
        source=('jobs:\n  hidden-private-name:\n    steps:\n'
                '      - run: curl https://private.example/secret && echo HIDDEN_PAYLOAD\n'
                '        env:\n          TOKEN: HIDDEN_PAYLOAD\n'
                '      - run: python3 verify.py --token HIDDEN_PAYLOAD\n'
                '      - uses: private/hidden-action@secret\n')
        result=self.scan(source);serialized=json.dumps(result)
        for marker in ('private.example','HIDDEN_PAYLOAD','hidden-private-name','hidden-action','--token'):
            self.assertNotIn(marker,serialized)
        self.assertEqual(self.observations(result,'command')[0]['command'],'python script')
        self.assertTrue(result['unknowns'])

    def test_reusable_flow_anchor_matrix_and_invalid_structure_are_explicit_limits(self):
        source=('jobs:\n  reusable:\n    uses: ./.github/workflows/shared.yml\n'
                '  check:\n    strategy:\n      matrix: {python: ["3.12"]}\n'
                '    defaults: &local\n      run:\n        working-directory: inner\n'
                '    steps:\n      - run: python3 build.py\n')
        result=self.scan(source)
        self.assertGreaterEqual(len(result['unknowns']),3)
        self.assertEqual(self.observations(result,'command')[0]['cwd'],None)
        self.assertEqual(self.observations(result,'script'),[])

    def test_unsupported_run_defaults_do_not_fall_back_to_root(self):
        source=('defaults:\n  run: {working-directory: nested}\njobs:\n  check:\n    steps:\n'
                '      - run: python3 forge.py\n')
        result=self.scan(source,{'forge.py':b'pass'})
        self.assertIsNone(self.observations(result,'command')[0]['cwd'])
        self.assertEqual(self.observations(result,'script'),[])
        self.assertTrue(result['unknowns'])

    def test_unknown_action_is_signposted_without_disclosing_reference(self):
        result=self.scan('jobs:\n  check:\n    steps:\n      - uses: private/hidden-action@secret\n')
        self.assertTrue(result['unknowns'])
        self.assertNotIn('hidden-action',json.dumps(result))

    def test_non_github_configs_are_signposted_without_claiming_parsed_jobs(self):
        result=discover_ci({'.gitlab-ci.yml':b'include: private.yml\n','Jenkinsfile':b'pipeline {}'})
        self.assertEqual(result['workflows'],[])
        self.assertEqual({r['source'] for r in result['unknowns']},{'.gitlab-ci.yml','Jenkinsfile'})

    def test_duplicate_working_directory_never_resolves_ambiguous_target(self):
        source=('defaults:\n  run:\n    working-directory: first\n'
                '    working-directory: second\njobs:\n  check:\n    steps:\n'
                '      - run: python3 build.py\n')
        result=self.scan(source,{'first/build.py':b'pass','second/build.py':b'pass'})
        self.assertEqual(result['workflows'][0]['observations'],[])
        self.assertTrue(any(row['line']==4 for row in result['unknowns']))
        self.assertNotIn('first/build.py',json.dumps(result))

    def test_duplicate_step_key_and_merge_cannot_resolve_partial_workflow(self):
        for lines in ('        working-directory: first\n        working-directory: second\n',
                      '        <<: *shared\n'):
            result=self.scan('jobs:\n  check:\n    steps:\n      - run: python3 build.py\n'+lines)
            self.assertEqual(result['workflows'][0]['observations'],[])
            self.assertTrue(result['unknowns'])

    def test_bounded_deep_and_wide_mappings_do_not_crash_or_infer_cwd(self):
        deep=''.join('  '*number+'x:\n' for number in range(999))
        self.assertLess(len(deep.encode()),1024*1024)
        for source in (deep, ''.join('key'+str(number)+': value\n' for number in range(5000))):
            result=self.scan(source)
            self.assertEqual(result['workflows'][0]['observations'],[])
            self.assertTrue(result['unknowns'])

    def test_static_make_and_python_deploy_cues_remain_production_only(self):
        result=self.scan('jobs:\n  check:\n    steps:\n      - run: make deploy\n'
                         '      - run: python3 ops/deploy.py\n'
                         '      - run: python3 verify.py\n')
        rows=self.observations(result,'command')
        self.assertEqual([r['local_appropriateness'] for r in rows],
                         ['production_only','production_only','requires_review'])
        self.assertTrue(all(not row['runtime_verified'] for row in rows))

    def test_safe_path_resolution_retains_nested_parent_script_but_rejects_escape(self):
        source=('defaults:\n  run:\n    working-directory: nested\njobs:\n  check:\n    steps:\n'
                '      - run: python3 ../tools/build.py\n      - run: python3 ../../outside.py\n')
        result=self.scan(source,{'tools/build.py':b'pass'})
        self.assertEqual([r['target'] for r in self.observations(result,'script')],['tools/build.py'])
        self.assertTrue(result['unknowns'])


if __name__=='__main__':unittest.main()
