"""Bounded artifact pointers, not a language interpreter or test oracle.

Only safe literal relative paths and syntactic test structure leave source. Values,
assertion operands, fixture contents and arbitrary command bodies stay private.
"""
import ast
import json
import posixpath
from pathlib import PurePosixPath
import re
import shlex

_SUFFIXES={'.sql','.json','.yaml','.yml','.py','.sh','.toml','.ini','.cfg','.schema','.contract'}
_SECRET=re.compile(r'secret|credential|^\.env(?:\.|$)|\.pem$|\.key$',re.I)


def _literal_path(value):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}',value):
        return False
    path=PurePosixPath(value)
    return not path.is_absolute() and path.suffix.lower() in _SUFFIXES and not any(_SECRET.search(p) for p in path.parts)


def _row(source,line,**values):
    return {'source':source,'line':line,'state':'declared','runtime_verified':False,**values}


def _qualified(node,aliases):
    if isinstance(node,ast.Name):return aliases.get(node.id,node.id)
    if isinstance(node,ast.Attribute):return _qualified(node.value,aliases)+'.'+node.attr
    if isinstance(node,ast.Call):return _qualified(node.func,aliases)
    return ''


def discover_repository(files):
    """Consume the existing sanitized file map; no filesystem reads/execution here."""
    report={'schema_version':1,'references':[],'tests':[],'fixtures':[],'unknowns':[],
            'limitations':['Literal relative-path candidates only; runtime cwd, computed paths and language semantics need source inspection.',
                           'Python test structure is declared expectation evidence, not passing-test or provider-fidelity evidence.',
                           'Only function-level syntactic test markers are extracted; class/module markers, import shadowing and dynamic collection remain unknown.',
                           'No assertion operands, mock targets, skip reasons, file contents or arbitrary commands are copied.']}
    names=set(files)
    seen=set()

    def reference(source,line,value):
        if not _literal_path(value):return
        candidates=[]
        for base,kind in (('', 'repository_root'),(str(PurePosixPath(source).parent),'source_directory')):
            target=posixpath.normpath(posixpath.join(base,value))
            if target=='..' or target.startswith('../') or target.startswith('/'):
                continue
            if any(c['path']==target for c in candidates):continue
            candidates.append({'path':target,'exists':target in names,'basis':kind,'state':'inferred'})
        if not candidates:return
        key=(source,line,value)
        if key in seen:return
        seen.add(key)
        count=sum(c['exists'] for c in candidates)
        report['references'].append(_row(source,line,candidates=candidates,
            resolution='ambiguous' if count>1 else 'candidate' if count else 'unresolved',
            resolution_scope='repository_root_and_source_directory_only'))

    for source,raw in sorted(files.items()):
        text=raw.decode('utf-8',errors='replace') if isinstance(raw,bytes) else str(raw)
        path=PurePosixPath(source)
        if path.suffix=='.py':
            try:tree=ast.parse(text)
            except (SyntaxError,ValueError,RecursionError) as error:
                report['unknowns'].append(_row(source,getattr(error,'lineno',None) or 1,
                    state='inferred',detail='Python structure unsupported or invalid; inspect source without executing it.'))
                continue
            aliases={}
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):
                    for name in node.names:aliases[name.asname or name.name.split('.')[0]]=name.name if name.asname else name.name.split('.')[0]
                if isinstance(node,ast.ImportFrom):
                    for name in node.names:aliases[name.asname or name.name]=(node.module or '')+'.'+name.name
                if isinstance(node,ast.Constant) and isinstance(node.value,str):
                    reference(source,node.lineno,node.value)
            for node in ast.walk(tree):
                if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                decorators=[(_qualified(d,aliases),d.lineno) for d in node.decorator_list]
                if any(name in {'pytest.fixture','pytest.fixture()'} for name,_ in decorators):
                    report['fixtures'].append(_row(source,node.lineno,name=node.name,detail='Syntactic fixture declaration; setup/data relationships require inspection.'))
                # A name is only a discovery pointer: runner collection remains unknown.
                if not node.name.startswith('test_'):continue
                assertions=[];mocks=[];skips=[];calls=[]
                for child in ast.walk(node):
                    if isinstance(child,ast.Assert):assertions.append(_row(source,child.lineno,kind='assert'))
                    if isinstance(child,ast.Call):
                        name=_qualified(child.func,aliases)
                        leaf=name.rsplit('.',1)[-1]
                        if leaf.startswith('assert') and re.fullmatch(r'assert[A-Z][A-Za-z0-9_]*',leaf):
                            assertions.append(_row(source,child.lineno,kind=leaf))
                        if name.startswith('unittest.mock.') or name.startswith('pytest_mock.') or name.startswith('mocker.'):
                            mocks.append(_row(source,child.lineno,kind='syntactic_mock_reference'))
                        if name in {'pytest.skip','pytest.xfail'}:skips.append(_row(source,child.lineno,kind='conditional_or_runtime_skip'))
                        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,100}',name):calls.append(_row(source,child.lineno,name=name))
                for name,line in decorators:
                    if name in {'unittest.skip','unittest.skipIf','unittest.skipUnless','pytest.mark.skip','pytest.mark.skipif','pytest.mark.xfail'}:
                        skips.append(_row(source,line,kind='skip_or_expected_failure_declaration'))
                report['tests'].append(_row(source,node.lineno,name=node.name,assertions=assertions,
                    mocks=mocks,skips=skips,calls=calls,collection='unverified',
                    detail='Read assertion inputs/outputs, setup and consumers to infer business rules; stale expectations and mocks require reconciliation.'))
        elif path.suffix in {'.sh','.bash'} or path.name=='Makefile':
            for line,content in enumerate(text.splitlines(),1):
                try:tokens=shlex.split(content,comments=True)
                except ValueError:
                    report['unknowns'].append(_row(source,line,state='inferred',detail='Shell tokenization unsupported; inspect command context.'))
                    continue
                for token in tokens:reference(source,line,token.split('=',1)[-1])
        elif path.name=='package.json':
            try:doc=json.loads(text)
            except (ValueError,TypeError):continue
            if not isinstance(doc,dict) or not isinstance(doc.get('scripts'),dict):continue
            for value in doc['scripts'].values():
                if not isinstance(value,str):continue
                try:tokens=shlex.split(value)
                except ValueError:continue
                line=next((i for i,s in enumerate(text.splitlines(),1) if json.dumps(value) in s),1)
                for token in tokens:reference(source,line,token.split('=',1)[-1])
    return report
