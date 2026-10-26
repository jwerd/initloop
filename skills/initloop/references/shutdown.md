# Owned shutdown proof

Record the actual reachable host, configured port, endpoint and owned process or
service identity at launch. Use that same target for readiness, useful requests
and shutdown checks. A bind wildcard such as `0.0.0.0` is not the probe address;
record its actual reachable loopback address. Never substitute a default or an
unused different port in the stop check.

Before stopping, demonstrate a successful request on that exact endpoint. After
stopping, require both termination/reaping of the recorded owned process and
closure of that same listener. HTTP errors, authentication failures, timeouts,
DNS/routing errors and an unused port are not shutdown proof. If either ownership
or closure is unproven, report it incomplete; do not signal an unrelated process.

## Direct foreground server example

This example is only for a single foreground Python server whose PID is the
actual service process. It assumes a trusted project configuration has already
selected `PORT`, `INITLOOP_PROBE_HOST` (a concrete loopback IP), `LOG_FILE` and
`PROJECT_DIR`; derive these from the actual launch, not a second port guess.
Adapt the module and public request path to the project. Existing project
supervision remains preferred when available.

Change directory separately from the background launch:

<!-- recipe: direct -->
```sh
cd "$PROJECT_DIR" || exit 1
: "${PORT:?actual configured port required}"
: "${LOG_FILE:?owned private log path required}"
: "${INITLOOP_PROBE_HOST:?actual reachable loopback IP required}"
export PORT INITLOOP_PROBE_HOST
python3 -m app.server >"$LOG_FILE" 2>&1 &
SERVER_PID=$!
export SERVER_PID
export INITLOOP_SERVER_PID="$SERVER_PID"
export INITLOOP_PROBE_PORT="$PORT"
export INITLOOP_PROBE_PATH="${INITLOOP_PROBE_PATH:-/health}"
```

Do not adapt this to `cd DIR && python3 -m app.server &` and assume `$!` is the
server. That backgrounds an AND-list/subshell; killing only its job/shell can
leave the server alive. Some shells optimize the last command into the server,
and interactive job control can signal a group; neither is a portable ownership
guarantee. `%1` requires a suitable job table/job-control context and is not a
portable PID or valid in every noninteractive shell. This is a warning about
ownership, not a blanket prohibition on shell commands.

Run the before proof in this same owning shell once the service is ready. A
failed startup request means retry readiness within a bound or investigate;
never reinterpret it as successful shutdown.

<!-- proof: before -->
```python
import http.client
import ipaddress
import os

host = os.environ['INITLOOP_PROBE_HOST']
if not ipaddress.ip_address(host).is_loopback:
    raise SystemExit('This example requires the actual concrete loopback IP')
port = int(os.environ['INITLOOP_PROBE_PORT'])
if not 1 <= port <= 65535:
    raise SystemExit('Invalid configured port')
path = os.environ['INITLOOP_PROBE_PATH']
if not path.startswith('/'):
    raise SystemExit('Use the actual request path')
connection = http.client.HTTPConnection(host, port, timeout=2)
try:
    connection.request('GET', path)
    response = connection.getresponse()
    if response.status != 200:
        raise SystemExit('Exact endpoint did not return the expected success')
    response.read(4096)
finally:
    connection.close()
print('Exact configured endpoint reachable before stop')
```

The owning shell can now stop and wait for its recorded direct child:

```sh
kill -TERM "$SERVER_PID"
wait "$SERVER_PID" || stop_status=$?
```

Record the actual exit outcome. For foreground terminal use, Ctrl-C targets that
owned foreground job; record its actual process identity before launch and wait
for exit. Do not look up an arbitrary PID by process name or port. A separate
shell cannot `wait` for another shell's child; use the actual owner or the
established named lifecycle. Never blindly signal a saved PID after losing its
ownership context. For multiprocess wrappers, use the existing runner's exact
owned lifecycle or Initloop's named-ledger supervisor with a foreground child;
a stopped launcher alone is not stopped services. See [controller.md](controller.md).

After the owning parent has waited/reaped the direct child (or validated the
named lifecycle's owned process exit), run this with the same recorded target.
It sends no signal. Presence/permission uncertainty is failure, not permission
to kill a possibly reused PID. A brief zombie must be reaped before claiming
process absence. Only a real connection refusal on the exact listener is a
positive closure result; other network failures are inconclusive.

<!-- proof: after -->
```python
import errno
import ipaddress
import os
import socket

host = os.environ['INITLOOP_PROBE_HOST']
if not ipaddress.ip_address(host).is_loopback:
    raise SystemExit('This example requires the actual concrete loopback IP')
port = int(os.environ['INITLOOP_PROBE_PORT'])
pid = int(os.environ['INITLOOP_SERVER_PID'])
if not 1 <= port <= 65535 or pid <= 1:
    raise SystemExit('Invalid recorded ownership or endpoint')
try:
    os.kill(pid, 0)
except ProcessLookupError:
    pass
except OSError:
    raise SystemExit('Owned process absence is unproven')
else:
    raise SystemExit('Recorded process still present; shutdown unproven')
try:
    connection = socket.create_connection((host, port), timeout=2)
except OSError as error:
    if error.errno != errno.ECONNREFUSED:
        raise SystemExit('Exact listener closure is inconclusive')
else:
    connection.close()
    raise SystemExit('Exact listener still accepts connections')
print('Owned process absent and exact configured listener refused connection')
```

These executable examples illustrate proof for one concrete HTTP loopback
service; they are not a new general supervisor or a production/network sandbox.
For Unix sockets, TLS, multiple listeners or workers, adapt to the actual owned
runner and prove every relevant resource, retaining unrelated services/data.
