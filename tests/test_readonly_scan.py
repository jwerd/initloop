"""Read-only discovery continues without weakening snapshot/execution boundaries."""
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from initloop.core import Inventory, PolicyError, snapshot
from initloop.workflow import audit, _files, propose, refresh


class ReadOnlyScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='initloop-readonly-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'project';self.root.mkdir()
        self.put('package.json','{"scripts":{"test":"node checks.js"}}')
        self.put('normal.py','from os import getenv\nPORT=getenv("PORT")\n')

    def put(self,name,text):
        target=self.root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text)
        return target

    def scan(self):
        from initloop.readonly_scan import scan
        return scan(self.root)

    def links(self):
        outside=Path(self.tmp.name)/'outside-private.txt';outside.write_text('synthetic-private-content-never-read')
        (self.root/'internal.py').symlink_to('normal.py')
        (self.root/'dangling').symlink_to('vendor/not-installed')
        (self.root/'external').symlink_to(outside)
        (self.root/'cycle-a').symlink_to('cycle-b');(self.root/'cycle-b').symlink_to('cycle-a')
        (self.root/'self').symlink_to('.')
        return outside

    def test_inventory_tracks_link_exclusions_and_still_discovers_useful_project(self):
        outside=self.links()
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
        result=Inventory(self.root).scan()
        self.assertTrue(any(row['manifest']=='package.json' for row in result['components']))
        scan=result['discovery_scan']
        self.assertEqual(scan['status'],'partial')
        reasons={row['reason'] for row in scan['findings']}
        self.assertTrue({'symlink_internal','symlink_dangling','symlink_external','symlink_cyclic'}.issubset(reasons))
        self.assertNotIn(str(outside),json.dumps(result))
        self.assertNotIn('synthetic-private-content',json.dumps(result))
        self.assertTrue(all(row['state']=='observed' for row in scan['findings']))

    def test_workflow_reports_links_without_reading_them_or_losing_normal_inputs(self):
        outside=self.links();result=audit(self.root)
        self.assertEqual(result['discovery_scan']['status'],'partial')
        self.assertIn('package.json',result['dependencies']);self.assertNotIn('internal.py',result['dependencies'])
        self.assertTrue(any(row.get('code')=='discovery_exclusion' for row in result['findings']))
        self.assertNotIn(str(outside),json.dumps(result))
        self.assertEqual(outside.read_text(),'synthetic-private-content-never-read')

    def test_dangling_launcher_does_not_prevent_discovery_without_git(self):
        (self.root/'launcher').symlink_to('vendor/bin/runner')
        result=Inventory(self.root).scan()
        self.assertTrue(result['components'])
        self.assertEqual(result['discovery_scan']['status'],'partial')
        self.assertIn('PORT',result['environment_names'])

    def test_regular_files_and_explicit_template_names_keep_existing_scan_contract(self):
        self.put('.env','SECRET_TOKEN=never-read')
        self.put('.env.example','SERVICE_URL=synthetic-example')
        self.put('vendor/lib.py','never-follow-dependencies')
        self.put('.agents/skills/other/tool.py','installed-helper-not-app')
        self.put('binary.bin','abc\0def')
        files,meta=self.scan()
        self.assertEqual(set(files),{'package.json','normal.py','.env.example'})
        self.assertEqual(meta['status'],'complete_within_scope')
        self.assertGreaterEqual(meta['excluded_count'],4)
        self.assertEqual(files,_files(self.root))

    def test_known_credential_and_runtime_inputs_are_not_read(self):
        for name in ('.netrc','.pypirc','auth.json','cert.p12','data.db','app.log','.ssh/config','.aws/config'):
            self.put(name,'PRIVATE_VALUE_NEVER_READ')
        files,metadata=self.scan()
        self.assertFalse(any(b'PRIVATE_VALUE' in raw for raw in files.values()))
        self.assertIn('normal.py',files)

    def test_direct_stack_discovery_carries_partial_scan_evidence(self):
        from initloop.stack import discover
        (self.root/'launcher').symlink_to('vendor/not-installed')
        result=discover(self.root)
        self.assertEqual(result['discovery_scan']['status'],'partial')
        self.assertTrue(result['runtimes'])

    def test_permission_failure_is_precise_partial_and_other_inputs_continue(self):
        import initloop.readonly_scan as module
        self.put('denied.py','DO_NOT_READ_VALUE')
        original=os.open
        def denied(name,*args,**kwargs):
            if name=='denied.py':raise PermissionError(errno.EACCES,'synthetic denied content value never copied')
            return original(name,*args,**kwargs)
        with patch.object(module.os,'open',side_effect=denied):
            files,meta=self.scan()
        self.assertIn('normal.py',files);self.assertNotIn('denied.py',files)
        row=next(r for r in meta['findings'] if r['source']=='denied.py')
        self.assertEqual(row['operation'],'read');self.assertEqual(row['errno'],'EACCES')
        self.assertEqual(meta['status'],'partial')
        self.assertNotIn('synthetic denied content',json.dumps(meta))

    def test_denied_directory_does_not_prevent_sibling_discovery(self):
        import initloop.readonly_scan as module
        self.put('locked/part.py','unavailable')
        original=os.open
        def denied(name,*args,**kwargs):
            if name=='locked':raise PermissionError(errno.EPERM,'simulated directory access denied')
            return original(name,*args,**kwargs)
        with patch.object(module.os,'open',side_effect=denied):files,meta=self.scan()
        self.assertIn('package.json',files);self.assertNotIn('locked/part.py',files)
        self.assertTrue(any(r['source']=='locked' and r['operation']=='list' and r['errno']=='EPERM' for r in meta['findings']))

    def test_external_link_is_not_statted_or_opened(self):
        outside=self.links();original_open=os.open;original_stat=os.stat
        def opened(name,*args,**kwargs):
            self.assertNotEqual(str(name),str(outside));return original_open(name,*args,**kwargs)
        def stated(name,*args,**kwargs):
            self.assertNotEqual(str(name),str(outside));return original_stat(name,*args,**kwargs)
        with patch('os.open',side_effect=opened),patch('os.stat',side_effect=stated):files,meta=self.scan()
        self.assertNotIn('external',files)
        self.assertTrue(any(r['reason']=='symlink_external' for r in meta['findings']))

    def test_source_changed_to_symlink_before_open_is_not_followed(self):
        import initloop.readonly_scan as module
        outside=Path(self.tmp.name)/'outside-private.txt';outside.write_text('never-read-race')
        victim=self.put('changing.py','ordinary')
        original=os.open
        def swap(name,*args,**kwargs):
            if name=='changing.py' and not victim.is_symlink():
                victim.unlink();victim.symlink_to(outside)
            return original(name,*args,**kwargs)
        with patch.object(module.os,'open',side_effect=swap):files,meta=self.scan()
        self.assertNotIn('changing.py',files)
        self.assertTrue(any(r['source']=='changing.py' for r in meta['findings']))
        self.assertNotIn('never-read-race',json.dumps(files,default=str))

    def test_missing_root_and_unsupported_descriptor_capability_are_explicit_partial(self):
        import initloop.readonly_scan as module
        files,meta=module.scan(self.root/'absent')
        self.assertEqual(files,{})
        self.assertEqual(meta['status'],'partial')
        self.assertEqual(meta['findings'][0]['errno'],'ENOENT')
        with patch.object(module.os,'name','unsupported'):
            files,meta=self.scan()
        self.assertEqual(files,{})
        self.assertEqual(meta['findings'][0]['reason'],'safe_descriptor_scan_unavailable')

    def test_per_entry_stat_and_read_failures_do_not_hide_independent_inputs(self):
        import initloop.readonly_scan as module
        self.put('vanished.py','irrelevant');blocked=self.put('unreadable.py','do-not-read')
        inode=blocked.stat().st_ino;original_stat=os.stat;original_fdopen=os.fdopen
        def stated(name,*args,**kwargs):
            if name=='vanished.py':raise FileNotFoundError(errno.ENOENT,'simulated disappearing entry')
            return original_stat(name,*args,**kwargs)
        def opened(fd,*args,**kwargs):
            if os.fstat(fd).st_ino==inode:raise PermissionError(errno.EACCES,'simulated read failure')
            return original_fdopen(fd,*args,**kwargs)
        with patch.object(module.os,'stat',side_effect=stated),patch.object(module.os,'fdopen',side_effect=opened):
            files,meta=self.scan()
        self.assertIn('normal.py',files)
        self.assertEqual({(r['source'],r['operation']) for r in meta['findings']},{('vanished.py','stat'),('unreadable.py','read')})

    def test_scandir_failure_is_reported_and_no_read_success_is_claimed(self):
        import initloop.readonly_scan as module
        with patch.object(module.os,'scandir',side_effect=PermissionError(errno.EACCES,'simulated enumerate denial')):
            files,meta=self.scan()
        self.assertEqual(files,{})
        self.assertEqual(meta['files_read'],0)
        self.assertEqual(meta['status'],'partial')
        self.assertEqual(meta['findings'][0]['source'],'.')

    def test_directory_swap_to_link_before_open_never_reads_external_children(self):
        import initloop.readonly_scan as module
        self.put('changing/old.py','ordinary')
        outside=Path(self.tmp.name)/'outside-dir';outside.mkdir();(outside/'private.py').write_text('PRIVATE_SENTINEL')
        original=os.open
        def swapped(name,*args,**kwargs):
            if name=='changing' and not (self.root/'changing').is_symlink():
                (self.root/'changing').rename(self.root/'old-dir')
                (self.root/'changing').symlink_to(outside,target_is_directory=True)
            return original(name,*args,**kwargs)
        with patch.object(module.os,'open',side_effect=swapped):files,meta=self.scan()
        self.assertFalse(any(b'PRIVATE_SENTINEL' in raw for raw in files.values()))
        self.assertTrue(any(r['source']=='changing' and r['operation']=='list' for r in meta['findings']))

    @unittest.skipUnless(hasattr(os,'mkfifo'),'nonregular POSIX input')
    def test_fifo_is_excluded_without_opening_or_blocking(self):
        os.mkfifo(self.root/'events.pipe')
        files,meta=self.scan()
        self.assertIn('normal.py',files)
        self.assertTrue(any(r['reason']=='nonregular_input' for r in meta['findings']))

    def test_link_metadata_resolution_handles_nested_internal_external_and_unresolved_paths(self):
        self.put('nested/data.py','permitted')
        (self.root/'directory-alias').symlink_to('nested',target_is_directory=True)
        (self.root/'nested-alias').symlink_to('directory-alias/data.py')
        (self.root/'root-alias').symlink_to(self.root.resolve(),target_is_directory=True)
        (self.root/'parent-escape').symlink_to('../outside/not-read')
        (self.root/'not-a-directory').symlink_to('normal.py/child')
        files,meta=self.scan();kinds={r['source']:r['reason'] for r in meta['findings']}
        self.assertEqual(kinds['nested-alias'],'symlink_internal')
        self.assertEqual(kinds['root-alias'],'symlink_internal')
        self.assertEqual(kinds['parent-escape'],'symlink_external')
        self.assertEqual(kinds['not-a-directory'],'symlink_unresolved')
        self.assertEqual(files['nested/data.py'],b'permitted')

    def test_symlink_chain_budget_and_directory_depth_are_explicit_partial(self):
        for index in range(42):(self.root/f'chain-{index}').symlink_to(f'chain-{index+1}' if index<41 else 'normal.py')
        deep='/'.join(['d']*66)+'/leaf.py';self.put(deep,'too deep')
        files,meta=self.scan()
        self.assertIn('normal.py',files);self.assertNotIn(deep,files)
        self.assertTrue(any(r['source']=='chain-0' and r['reason']=='symlink_unresolved' for r in meta['findings']))
        self.assertTrue(any(r['reason']=='directory_depth_budget' for r in meta['findings']))

    def test_refresh_keeps_new_exclusions_visible_even_if_included_hashes_match(self):
        result=propose(self.root,Path(self.tmp.name)/'proposal','reconcile')
        manifest=Path(result['manifest_path'])
        saved=json.loads(manifest.read_text())
        self.assertEqual(saved['discovery_scan']['status'],'complete_within_scope')
        frozen=manifest.read_bytes()
        (self.root/'new-launcher').symlink_to('vendor/not-installed')
        current=refresh(self.root,manifest)
        self.assertTrue(current['inputs_unchanged'])
        self.assertTrue(current['discovery_scan_changed'])
        self.assertEqual(current['discovery_scan']['status'],'partial')
        self.assertEqual(current['status'],'unverified')
        self.assertTrue(current['revalidation_required'])
        self.assertEqual(frozen,manifest.read_bytes())
        saved.pop('discovery_scan')
        legacy=Path(self.tmp.name)/'legacy-manifest.json';legacy.write_text(json.dumps(saved))
        legacy_result=refresh(self.root,legacy)
        self.assertIsNone(legacy_result['discovery_scan_changed'])
        self.assertEqual(legacy_result['discovery_scan']['status'],'partial')

    def init_committed_repo(self,path):
        subprocess.run(['git','init','-q',str(path)],check=True)
        subprocess.run(['git','-C',str(path),'-c','user.name=Synthetic fixture',
                        '-c','user.email=synthetic@example.invalid','commit','--allow-empty','-qm','Synthetic baseline '+path.name],check=True)
        return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True).strip()

    def test_git_symlink_provenance_cannot_read_outside_repository(self):
        outside=Path(self.tmp.name)/'outside-git';outside.mkdir()
        outside_revision=self.init_committed_repo(outside)
        (self.root/'.git').symlink_to(outside/'.git',target_is_directory=True)
        # No provenance subprocess is permitted once discovery excluded .git.
        with patch('initloop.workflow.subprocess.run',wraps=subprocess.run) as query:
            result=audit(self.root)
        self.assertIsNone(result['repository']['revision'],outside_revision)
        self.assertIsNone(result['repository']['dirty'])
        self.assertEqual(query.call_count,0)
        self.assertEqual(result['repository']['provenance']['reason'],'metadata_excluded')
        self.assertIn('package.json',result['dependencies'])
        self.assertTrue(any(r['code']=='git_provenance_unavailable' for r in result['findings']))
        self.assertNotIn(outside_revision,json.dumps(result))

    def test_git_provenance_does_not_walk_ancestor_repo_without_own_marker(self):
        parent_revision=self.init_committed_repo(Path(self.tmp.name))
        with patch('initloop.workflow.subprocess.run',wraps=subprocess.run) as query:
            result=audit(self.root)
        self.assertIsNone(result['repository']['revision'],parent_revision)
        self.assertEqual(query.call_count,0)
        self.assertEqual(result['repository']['provenance']['reason'],'metadata_absent')

    def test_normal_git_and_regular_worktree_marker_preserve_own_provenance(self):
        revision=self.init_committed_repo(self.root)
        ordinary=audit(self.root)
        self.assertEqual(ordinary['repository']['revision'],revision)
        self.assertEqual(ordinary['repository']['provenance']['status'],'observed')
        worktree=Path(self.tmp.name)/'worktree'
        subprocess.run(['git','-C',str(self.root),'worktree','add','--detach','-q',str(worktree)],check=True)
        self.assertTrue((worktree/'.git').is_file());self.assertFalse((worktree/'.git').is_symlink())
        result=audit(worktree)
        self.assertEqual(result['repository']['revision'],revision)
        self.assertEqual(result['repository']['provenance']['status'],'observed')

    def test_ambient_git_location_override_cannot_redirect_provenance(self):
        revision=self.init_committed_repo(self.root)
        outside=Path(self.tmp.name)/'other-git';outside.mkdir();outside_revision=self.init_committed_repo(outside)
        env={'GIT_DIR':str(outside/'.git'),'GIT_WORK_TREE':str(outside),'GIT_COMMON_DIR':str(outside/'.git'),
             'GIT_INDEX_FILE':str(outside/'.git/index'),'GIT_OBJECT_DIRECTORY':str(outside/'.git/objects'),
             'GIT_ALTERNATE_OBJECT_DIRECTORIES':str(outside/'.git/objects')}
        with patch.dict(os.environ,env):result=audit(self.root)
        self.assertEqual(result['repository']['revision'],revision,outside_revision)
        self.assertEqual(result['repository']['provenance']['ambient_location_overrides_omitted'],sorted(env))
        self.assertNotIn(str(outside),json.dumps(result))

    def test_git_metadata_access_failure_is_reported_without_a_query(self):
        self.init_committed_repo(self.root)
        original=Path.lstat
        def denied(path,*args,**kwargs):
            if path.name=='.git':raise PermissionError(errno.EACCES,'simulated private metadata text')
            return original(path,*args,**kwargs)
        with patch.object(Path,'lstat',denied),patch('initloop.workflow.subprocess.run') as query:
            result=audit(self.root)
        self.assertEqual(query.call_count,0)
        self.assertEqual(result['repository']['provenance']['reason'],'metadata_inaccessible')
        self.assertEqual(result['repository']['provenance']['errno'],'EACCES')
        self.assertNotIn('private metadata text',json.dumps(result))

    @unittest.skipUnless(hasattr(os,'mkfifo'),'nonregular POSIX metadata')
    def test_nonregular_git_marker_is_not_passed_to_git(self):
        os.mkfifo(self.root/'.git')
        with patch('initloop.workflow.subprocess.run') as query:result=audit(self.root)
        self.assertEqual(query.call_count,0)
        self.assertEqual(result['repository']['provenance']['reason'],'metadata_excluded')

    def test_git_query_failures_preserve_static_discovery_and_precise_unknowns(self):
        self.init_committed_repo(self.root)
        cases=[(FileNotFoundError(errno.ENOENT,'simulated unavailable git'),'query_unavailable'),
               (subprocess.TimeoutExpired(['git'],5),'query_timeout'),
               (subprocess.CompletedProcess(['git'],128,'','private git error'),'head_unavailable')]
        for response,reason in cases:
            options={'side_effect':response} if isinstance(response,Exception) else {'return_value':response}
            with self.subTest(reason=reason),patch('initloop.workflow.subprocess.run',**options):
                result=audit(self.root)
            self.assertIsNone(result['repository']['revision'])
            self.assertEqual(result['repository']['provenance']['reason'],reason)
            self.assertIn('package.json',result['dependencies'])
            self.assertNotIn('private git error',json.dumps(result))
        head=subprocess.CompletedProcess(['git'],0,'a'*40+'\n','')
        state=subprocess.CompletedProcess(['git'],1,'','private status error')
        with patch('initloop.workflow.subprocess.run',side_effect=[head,state]) as query:
            result=audit(self.root)
        self.assertEqual(result['repository']['revision'],'a'*40)
        self.assertIsNone(result['repository']['dirty'])
        self.assertEqual(result['repository']['provenance']['status'],'partial')
        self.assertEqual(result['repository']['provenance']['reason'],'status_unavailable')
        for call in query.call_args_list:self.assertEqual(call.kwargs['env']['GIT_OPTIONAL_LOCKS'],'0')
        self.assertNotIn('private status error',json.dumps(result))

    def test_nontrivial_parent_segments_are_unresolved_before_link_metadata_is_collapsed(self):
        outside=Path(self.tmp.name)/'outside';(outside/'subdir').mkdir(parents=True)
        (outside/'marker.txt').write_text('PRIVATE_OUTSIDE_MARKER')
        self.put('marker.txt','permitted project marker')
        (self.root/'alias').symlink_to(outside/'subdir',target_is_directory=True)
        (self.root/'dotdot-link').symlink_to('alias/../marker.txt')
        (self.root/'absolute-dotdot').symlink_to(str(self.root.resolve())+'/alias/../marker.txt')
        (self.root/'through-link').symlink_to('dotdot-link')
        self.put('tools/a.py','permitted');(self.root/'bin').mkdir()
        (self.root/'bin/leading-parent').symlink_to('../tools/a.py')
        files,meta=self.scan();reasons={r['source']:r['reason'] for r in meta['findings']}
        for name in ('dotdot-link','absolute-dotdot','through-link'):
            self.assertEqual(reasons[name],'symlink_unresolved')
        self.assertEqual(reasons['bin/leading-parent'],'symlink_internal')
        self.assertFalse(any(b'PRIVATE_OUTSIDE_MARKER' in raw for raw in files.values()))

    def test_snapshot_still_rejects_even_internal_links(self):
        (self.root/'internal.py').symlink_to('normal.py')
        subprocess.run(['git','init','-q',str(self.root)],check=True)
        subprocess.run(['git','-C',str(self.root),'add','.'],check=True)
        with self.assertRaises(PolicyError):snapshot(self.root,Path(self.tmp.name)/'snapshot')


if __name__=='__main__':unittest.main()
