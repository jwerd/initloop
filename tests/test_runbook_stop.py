"""Execute runbook examples against owned servers; never infer stop from any failure."""
import errno
import os
from pathlib import Path
import re
import signal
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest

REFERENCE = Path(os.environ.get('INITLOOP_TEST_SHUTDOWN_REFERENCE',
    str(Path(__file__).resolve().parents[1]/'skills/initloop/references/shutdown.md')))
SERVER = '''import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(503 if self.path=="/error" else 200)
        self.end_headers()
        self.wfile.write(b"synthetic owned server")
    def log_message(self,*args):pass
server=HTTPServer((os.environ.get("HOST","127.0.0.1"),int(os.environ["PORT"])),Handler)
Path(os.environ["PIDFILE"]).write_text(str(os.getpid()))
server.serve_forever()
'''


@unittest.skipUnless(os.name == 'posix', 'owned shell lifecycle requires POSIX')
class RunbookStopTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='initloop-runbook-stop-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        (self.root/'app').mkdir()
        (self.root/'app/__init__.py').write_text('')
        (self.root/'app/server.py').write_text(SERVER)
        self.processes=[]
        self.addCleanup(self.cleanup)
        self.counter=0
        self.sentinel,self.sentinel_env=self.start_server()

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                try:os.killpg(process.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid,signal.SIGKILL)
                    process.wait(timeout=3)

    def free_port(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port=sock.getsockname()[1]
        self.assertNotIn(port,(8000,18099))
        return port

    def environment(self):
        self.counter+=1
        port=self.free_port()
        return dict(os.environ,PROJECT_DIR=str(self.root),HOST='127.0.0.1',PORT=str(port),
            INITLOOP_PROBE_HOST='127.0.0.1',INITLOOP_PROBE_PORT=str(port),INITLOOP_PROBE_PATH='/health',
            PIDFILE=str(self.root/f'pid-{self.counter}'),JOBFILE=str(self.root/f'job-{self.counter}'),
            LOG_FILE=str(self.root/f'log-{self.counter}'),STOP_FILE=str(self.root/f'stop-{self.counter}'),STOP_STATUS=str(self.root/f'status-{self.counter}'),INITLOOP_LEGACY_WRONG_PORT=str(self.free_port()),PYTHONDONTWRITEBYTECODE='1')

    def start_process(self,argv,env):
        process=subprocess.Popen(argv,cwd=self.root,env=env,start_new_session=True,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.processes.append(process)
        return process

    def read_pid(self,path,process):
        for _ in range(150):
            if Path(path).exists():
                value=Path(path).read_text().strip()
                if value.isdigit():return int(value)
            if process.poll() is not None:self.fail('owned launch exited before recording identity')
            time.sleep(.02)
        self.fail('owned launch did not record identity')

    def start_server(self):
        env=self.environment()
        process=self.start_process([sys.executable,'-m','app.server'],env)
        actual=self.read_pid(env['PIDFILE'],process)
        self.assertEqual(actual,process.pid)
        env['INITLOOP_SERVER_PID']=str(actual)
        return process,env

    def listening(self,env):
        with socket.create_connection((env['INITLOOP_PROBE_HOST'],int(env['INITLOOP_PROBE_PORT'])),timeout=1):
            return True

    def stopped(self,process):
        process.terminate()
        process.wait(timeout=3)

    def snippet(self,kind,language='python'):
        text=REFERENCE.read_text()
        match=re.search(r'<!--\s*'+re.escape(kind)+r'\s*-->\s*```'+language+r'\n(.*?)```',text,re.S)
        self.assertIsNotNone(match,'missing executable runbook block')
        return match.group(1)

    def proof(self,phase,env):
        return subprocess.run([sys.executable,'-c',self.snippet('proof: '+phase)],env=env,
            capture_output=True,text=True,timeout=5)

    def sentinel_alive(self):
        self.assertIsNone(self.sentinel.poll())
        self.assertTrue(self.listening(self.sentinel_env))

    def test_wrong_port_can_false_pass_but_actual_endpoint_and_pid_proofs_detect_it(self):
        process,env=self.start_server()
        wrong=dict(env,INITLOOP_PROBE_PORT=str(self.free_port()))
        with socket.socket() as probe:
            probe.settimeout(1)
            self.assertNotEqual(probe.connect_ex(('127.0.0.1',int(wrong['INITLOOP_PROBE_PORT']))),0)
        self.assertTrue(self.listening(env))
        print('LEGACY false shutdown: unused different port fails while owned actual endpoint is alive')
        self.assertNotEqual(self.proof('before',wrong).returncode,0)
        self.assertEqual(self.proof('before',env).returncode,0)
        self.assertNotEqual(self.proof('after',env).returncode,0)
        self.stopped(process)
        self.assertEqual(self.proof('after',env).returncode,0)
        self.sentinel_alive()

    def test_http_error_is_not_shutdown_or_successful_preflight(self):
        process,env=self.start_server()
        self.assertNotEqual(self.proof('before',dict(env,INITLOOP_PROBE_PATH='/error')).returncode,0)
        self.assertTrue(self.listening(env))
        self.assertNotEqual(self.proof('after',env).returncode,0)
        self.stopped(process)
        self.assertEqual(self.proof('after',env).returncode,0)
        self.sentinel_alive()

    def test_listener_closure_alone_does_not_prove_owned_process_termination(self):
        env=self.environment()
        process=self.start_process([sys.executable,'-c','import time; time.sleep(60)'],env)
        env['INITLOOP_SERVER_PID']=str(process.pid)
        self.assertNotEqual(self.proof('after',env).returncode,0)
        self.stopped(process)
        self.assertEqual(self.proof('after',env).returncode,0)
        self.sentinel_alive()

    def test_direct_recipe_rejects_missing_project_before_launch(self):
        env=self.environment()
        env['PROJECT_DIR']=str(self.root/'missing-project')
        script=self.snippet('recipe: direct','sh')+'\nprintf "%s\\n" "$SERVER_PID" > "$JOBFILE"\nwait "$SERVER_PID"\nsleep 30\n'
        wrapper=self.start_process(['/bin/sh','-c',script],env)
        # The previous cwd intentionally contains an importable app: failed cd
        # must abort rather than silently launch that unrelated local copy.
        for _ in range(100):
            if wrapper.poll() is not None or Path(env['PIDFILE']).exists():break
            time.sleep(.01)
        self.assertIsNotNone(wrapper.poll(),'failed project cd must stop the launch shell')
        self.assertNotEqual(wrapper.returncode,0)
        self.assertFalse(Path(env['PIDFILE']).exists(),'failed cd launched an ambient app')
        self.assertFalse(Path(env['JOBFILE']).exists(),'failed cd created ownership metadata')
        self.sentinel_alive()

    def test_direct_recipe_exports_shell_local_probe_host_to_proof(self):
        env=self.environment()
        env.pop('INITLOOP_PROBE_HOST',None)
        script='INITLOOP_PROBE_HOST=127.0.0.1\n'+self.snippet('recipe: direct','sh')
        script+='\nprintf "%s\\n" "$SERVER_PID" > "$JOBFILE"\nwhile [ ! -f "$STOP_FILE" ]; do sleep .02; done\n'
        script+='python3 -c '+shlex.quote(self.snippet('proof: before'))+' >"$LOG_FILE.proof" 2>&1\nprintf "%s\\n" "$?" > "$STOP_STATUS"\nwait "$SERVER_PID"\nsleep 30\n'
        wrapper=self.start_process(['/bin/sh','-c',script],env)
        job=self.read_pid(env['JOBFILE'],wrapper)
        self.assertEqual(job,self.read_pid(env['PIDFILE'],wrapper))
        Path(env['STOP_FILE']).write_text('prove exact endpoint from inherited metadata')
        status=self.read_pid(env['STOP_STATUS'],wrapper)
        self.assertEqual(status,0,Path(env['LOG_FILE']+'.proof').read_text())
        self.sentinel_alive()

    def test_chained_cd_shell_characterization_and_documented_direct_recipe(self):
        shell='/bin/bash'
        if not Path(shell).is_file():self.skipTest('Bash not available for reported AND-list reproduction')
        env=self.environment()
        # Exact reported adaptation. Owning shell remains alive for bounded cleanup.
        script='cd "$PROJECT_DIR" && python3 -m app.server >"$LOG_FILE" 2>&1 &\njob=$!\nprintf "%s\\n" "$job" > "$JOBFILE"\nwhile [ ! -f "$STOP_FILE" ]; do sleep .02; done\nkill %1\nprintf "%s\\n" "$?" > "$STOP_STATUS"\nwait "$job"\nsleep 30\n'
        wrapper=self.start_process([shell,'+m','-c',script],env)
        job=self.read_pid(env['JOBFILE'],wrapper)
        actual=self.read_pid(env['PIDFILE'],wrapper)
        Path(env['STOP_FILE']).write_text('stop own job')
        self.assertEqual(self.read_pid(env['STOP_STATUS'],wrapper),0)  # Current owning Bash job table only.
        for _ in range(100):
            try:os.kill(job,0)
            except ProcessLookupError:break
            time.sleep(.01)
        with self.assertRaises(ProcessLookupError):os.kill(job,0)
        if job != actual:
            self.assertTrue(self.listening(env))
            self.assertNotEqual(self.proof('after',dict(env,INITLOOP_SERVER_PID=str(job))).returncode,0)
            print('AND-list orphan reproduced: job PID differs from live server PID')
        else:
            # Some shells tail-exec; characterize rather than claim universal failure.
            with socket.socket() as probe:self.assertEqual(probe.connect_ex(('127.0.0.1',int(env['PORT']))),errno.ECONNREFUSED)
            print('AND-list tail-exec variant: job PID is server PID; no orphan in this context')
        # Kill only the private group with its still-live owning wrapper.
        self.assertIsNone(wrapper.poll())
        os.killpg(wrapper.pid,signal.SIGTERM);wrapper.wait(timeout=3)
        safe=self.environment()
        script=self.snippet('recipe: direct','sh')+'\nprintf "%s\\n" "$SERVER_PID" > "$JOBFILE"\nwait "$SERVER_PID"\nsleep 30\n'
        wrapper=self.start_process([shell,'-c',script],safe)
        job=self.read_pid(safe['JOBFILE'],wrapper);actual=self.read_pid(safe['PIDFILE'],wrapper)
        self.assertEqual(job,actual,'documented direct recipe must record the actual server child')
        safe['INITLOOP_SERVER_PID']=str(job)
        self.assertEqual(self.proof('before',safe).returncode,0)
        os.kill(job,signal.SIGTERM)
        for _ in range(100):
            try:os.kill(job,0)
            except ProcessLookupError:break
            time.sleep(.01)
        self.assertEqual(self.proof('after',safe).returncode,0)
        self.sentinel_alive()


if __name__=='__main__':unittest.main()
