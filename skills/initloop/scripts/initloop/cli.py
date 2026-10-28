"""Machine-readable helper interface; models and agents remain in the harness."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

from .core import Inventory, PolicyError, Run, redact
from .backend import DockerBackend
from .native import NativeBackend


def main(argv=None):
    parser=argparse.ArgumentParser(description='Initloop deterministic skill helpers (no model or authentication runtime)')
    sub=parser.add_subparsers(dest='command',required=True)
    audit=sub.add_parser('audit',help='static inventory; not runtime certification'); audit.add_argument('project',type=Path)
    create=sub.add_parser('begin',help='freeze contract and isolated baseline'); create.add_argument('project',type=Path); create.add_argument('--runs',type=Path,required=True); create.add_argument('--contract',type=Path,required=True); create.add_argument('--include-dirty',action='store_true')
    execute=sub.add_parser('execute',help='bounded project command in explicit native or constrained Docker runtime'); execute.add_argument('workspace',type=Path); execute.add_argument('--image'); execute.add_argument('--runner',choices=['docker','native'],default='docker'); execute.add_argument('--timeout',type=int,default=60); execute.add_argument('argv',nargs=argparse.REMAINDER)
    baseline=sub.add_parser('baseline',help='run frozen acceptance against baseline'); baseline.add_argument('run',type=Path); baseline.add_argument('--image'); baseline.add_argument('--runner',choices=['docker','native'],default='docker')
    repair=sub.add_parser('repair',help='generate isolated patch from JSON path/text or explicit content/mode mapping'); repair.add_argument('run',type=Path); repair.add_argument('--files',type=Path,required=True)
    verify=sub.add_parser('verify',help='run frozen acceptance twice from fresh runtime state'); verify.add_argument('run',type=Path); verify.add_argument('--image'); verify.add_argument('--runner',choices=['docker','native'],default='docker')
    report=sub.add_parser('report'); report.add_argument('run',type=Path)
    cancel=sub.add_parser('cancel'); cancel.add_argument('run',type=Path)
    cleanup=sub.add_parser('cleanup',help='recover only recorded owned containers'); cleanup.add_argument('--ledger',type=Path)
    workflow=sub.add_parser('workflow',help='instruction proposal only, never applies to source'); workflow.add_argument('project',type=Path); workflow.add_argument('--destination',type=Path); workflow.add_argument('--mode',choices=['preserve','reconcile','replace'],default='preserve'); workflow.add_argument('--select',action='append',default=[])
    refresh=sub.add_parser('refresh',help='detect stale evidence; regeneration is not verification'); refresh.add_argument('project',type=Path); refresh.add_argument('--manifest',type=Path,required=True)
    decisions=sub.add_parser('checkpoint',help='persistent dependency planning only; no setup execution')
    decisions.add_argument('directory',type=Path)
    decisions.add_argument('--action',choices=['create','revise','show','investigate','findings','select','accept','review','back','cancel','resume','interactive'],default='show')
    decisions.add_argument('--project',type=Path); decisions.add_argument('--catalog',type=Path)
    decisions.add_argument('--dependency',action='append',default=[])
    decisions.add_argument('--option'); decisions.add_argument('--finding')
    decisions.add_argument('--affected',action='append',default=[])
    dev=sub.add_parser('dev',help='owned native foreground development lifecycle; not a sandbox')
    dev.add_argument('action',choices=['start','status','logs','stop','reset']); dev.add_argument('--ledger',type=Path,required=True); dev.add_argument('--name',required=True)
    dev.add_argument('--project',type=Path)
    raw=list(argv if argv is not None else sys.argv[1:]); dev_argv=[]
    if raw and raw[0]=='dev' and '--' in raw:
        separator=raw.index('--'); dev_argv=raw[separator+1:]; raw=raw[:separator]
    args=parser.parse_args(raw)
    if args.command=='dev':args.argv=dev_argv
    try:
        if args.command in {'execute','baseline','verify'}:
            if args.runner=='docker' and not args.image:raise PolicyError('Docker execution requires --image; choose --runner native explicitly for authorized host execution')
            backend=NativeBackend() if args.runner=='native' else DockerBackend(getattr(args,'run',None)/'resources' if getattr(args,'run',None) else None)
        if args.command=='checkpoint':
            from .decisions import Checkpoint, interactive
            if args.action=='create':
                if not args.project or not args.catalog:raise ValueError('create requires --project and --catalog')
                cp=Checkpoint.create(args.project,args.directory,json.loads(args.catalog.read_text()))
            else:cp=Checkpoint(args.directory)
            if args.action in {'select','findings'} and len(args.dependency)!=1:
                raise ValueError('select/findings requires exactly one --dependency')
            if args.action=='revise':
                if not args.catalog:raise ValueError('revise requires --catalog from reinspection')
                cp.revise(json.loads(args.catalog.read_text()))
            elif args.action=='investigate':cp.investigate(args.dependency)
            elif args.action=='accept':cp.accept_recommendations()
            elif args.action=='select':cp.select(args.dependency[0],args.option)
            elif args.action=='findings':cp.findings(args.dependency[0],args.finding,args.affected)
            elif args.action in {'review','back','cancel','resume'}:getattr(cp,args.action)()
            elif args.action=='interactive':
                interactive(cp)
                return 0
            result=cp.state
        elif args.command=='audit': result=Inventory(args.project).scan()
        elif args.command=='begin':
            run=Run.create(args.project,args.runs,json.loads(args.contract.read_text()),args.include_dirty); result={'run':str(run.root),'state':run.state}
        elif args.command=='execute':
            command=args.argv[1:] if args.argv and args.argv[0]=='--' else args.argv
            result=backend.execute(args.workspace,args.image,command,args.timeout)
        elif args.command=='baseline':
            run=Run(args.run); contract=run.check_contract()
            results=[dict(backend.execute(run.root/'baseline',args.image,c['argv'],c.get('timeout',60)),name=c['name']) for c in contract['checks']]
            run.record_baseline(results); result={'run':str(run.root),'results':results}
        elif args.command=='repair': result=Run(args.run).patch(json.loads(args.files.read_text()))
        elif args.command=='verify': result=Run(args.run).verify(backend,args.image)
        elif args.command=='dev':
            from .lifecycle import Service
            service=Service(args.ledger,args.name)
            if args.action=='start':
                if not args.project:raise PolicyError('dev start requires --project')
                command=args.argv[1:] if args.argv and args.argv[0]=='--' else args.argv
                result=service.start(args.project,command)
            else:result=getattr(service,args.action)()
        elif args.command=='cleanup': result={'resources':DockerBackend(args.ledger).cleanup()}
        elif args.command=='report': result=Run(args.run).report()
        elif args.command=='cancel':
            run=Run(args.run); run.transition('cancelled'); result=run.report()
        elif args.command=='workflow':
            from .workflow import audit,propose
            result=propose(args.project,args.destination,args.mode,args.select) if args.destination else audit(args.project)
        elif args.command=='refresh':
            from .workflow import refresh
            result=refresh(args.project,args.manifest)
        print(json.dumps(result,indent=2,sort_keys=True))
        if args.command=='verify' and result['status']!='verified': return 1
        if args.command=='execute' and result['exit_code']!=0: return 1
        if args.command=='cleanup' and any(r['status']!='removed' for r in result['resources']): return 1
        return 0
    except (PolicyError,ValueError,OSError,subprocess.SubprocessError) as exc:
        print(json.dumps({'status':'blocked','error':redact(str(exc))}),file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
