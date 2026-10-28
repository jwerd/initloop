# Controller commands and evidence

The helper is a local deterministic program, not an AI runtime. Python 3.9+ and Git are needed for static work. Execution uses the selected project runner; Docker with locally prepared trusted Linux images is needed only for the disposable Docker backend. Native host execution is explicitly available below. No external application fixture is bundled or imported.

```
python3 skills/initloop/scripts/initloop.py audit /absolute/project
python3 skills/initloop/scripts/initloop.py workflow /absolute/project
python3 skills/initloop/scripts/initloop.py begin /absolute/project --runs /outside/runs --contract /outside/contract.json
python3 skills/initloop/scripts/initloop.py baseline /outside/runs/RUN_ID --image python:3.12-alpine
python3 skills/initloop/scripts/initloop.py repair /outside/runs/RUN_ID --files /outside/changes.json
python3 skills/initloop/scripts/initloop.py verify /outside/runs/RUN_ID --image python:3.12-alpine
python3 skills/initloop/scripts/initloop.py report /outside/runs/RUN_ID
```

`execute` accepts only an unchanged controller-created baseline/repair snapshot with its digest receipt stored outside the input directory. An arbitrary checkout, home directory, or manually copied/modified workspace is refused. Keep receipts outside agent-visible snapshots; they are trusted controller metadata, not protection against hostile same-user host tools. Use `begin`/`repair` to create new sanitized inputs.

For an individual command, put helper options before the snapshot positional argument (the remainder is the project command):

```
python3 skills/initloop/scripts/initloop.py execute --image python:3.12-alpine --timeout 60 /outside/snapshot -- python -m unittest
```

Every Docker execution copies a read-only input to fresh tmpfs, then uses network `none` (loopback remains available), an unprivileged user, a read-only root, dropped capabilities, no new privileges, PID/memory/CPU/output/time limits and no host credential forwarding. Files created by the app disappear with the container. Run a multi-process workflow within one command/container to test shared local data and services. This backend does not yet manage Compose topologies or export mutated workspaces. It resolves local image tags to immutable IDs and never silently pulls an image or executes on the host. Preparing images/dependencies is a separate trusted, authorized network phase; never send secrets in build context/layers.

Contract example (controller-only input):

```json
{
  "objective": "Create and read a synthetic record, then prove a small change/test cycle",
  "protected_paths": ["tests/test_records.py"],
  "checks": [{
    "name": "persisted-record",
    "source": "user objective and checked-in tests/test_records.py at pinned revision",
    "argv": ["python", "-c", "import sqlite3; c=sqlite3.connect('/tmp/probe.db'); c.execute('create table records(id integer)'); c.execute('insert into records values (1)'); c.commit(); c.close(); assert sqlite3.connect('/tmp/probe.db').execute('select id from records').fetchone()==(1,)"],
    "exit_code": 0,
    "timeout": 60
  }]
}
```

The example tests SQLite, not an application's business behavior. Supply independent assertions derived from the actual project's API/contracts/tests. Use controller-owned inline assertion commands or protect every referenced evaluator input. Project-owned checks that the repair can change are insufficient. Do not place hidden answers or evaluators inside the agent-visible snapshot. Host-side access by the same OS user is outside the helper's security boundary; state hashes are tamper detection against snapshot mutation, not protection from a hostile controller user.

Run directories contain baseline, contract, state/events, attempt-specific repairs/diffs, baseline-results and verification results. Checkpoint hashes bind acceptance and repair inputs. Verification uses two clean containers per check and records exit state, redacted output, resolved image and duration. Separate checks do not share databases. A passed result covers only the supplied assertions. No checks gives a partial result. A resumed run must preserve its original contract; changed behavior expectations require a new run.

Each container is recorded before launch in an external resource ledger. Normal teardown removes that exact name. If interrupted or Docker becomes unavailable, use `cleanup --ledger RUN/resources` (or `cleanup` for standalone executions) to recover recorded containers after checking their ownership label. No global Docker prune is used. Pending cleanup prevents verification success. Missing/unreachable resources remain explicit records to investigate; do not edit the ledger to fabricate successful teardown.

Changes JSON maps relative paths to complete file text. For explicit permissions, a value can instead be an object with `content` and `mode` (only the strings `"0644"` or `"0755"`):

```json
{
  "README.md": "Run make setup, then make serve.\n",
  "scripts/setup.sh": {"content": "#!/bin/sh\nset -eu\npython3 scripts/local.py setup\n", "mode": "0755"}
}
```

Text-only values retain existing executable bits; new text files default to `0644`. Executability is never inferred. The frozen baseline contents and executable modes are rechecked before repair construction. Traversal, symlinks, structural file/directory collisions, secret/runtime paths, protected evaluator inputs and oversized files are refused. Failed construction retains diagnostic evidence without replacing earlier snapshots. Generated Git patches include explicit mode and missing-final-newline metadata. Deleted files, binary repairs and automatic application to the source checkout are intentionally unsupported. A later repair attempt is regenerated from the baseline, so submit the complete desired cumulative file map. Credential screening distinguishes quoted literal values and bare configuration values from computed expressions; ordinary `token = os.getenv("TOKEN")`, declared member expressions such as `const token = request.headers.authorization`, and harmless null defaults are not credentials. Bare dotted configuration values remain screened; declaration-free property assignments can be conservatively rejected. Recognizable credential formats remain screened wherever they occur. This is a conservative heuristic, not a language parser or proof that source has no secrets. Output redaction covers common JSON credential fields as well as existing assignment/bearer/URL patterns; deeply nested or repeatedly encoded output can be omitted when safe inspection exceeds its bounded budget. Novel formats can still escape best-effort filtering. Avoid logging secrets at source.

Run state is trusted controller data; never let agents edit it directly or claim an agent-written result file is independent execution evidence.

Unverified drafts can be revised with another complete `repair` mapping; each revision consumes the existing three-attempt budget and preserves earlier snapshots/diffs. Verified runs remain terminal. Compiled builds may use executable `/workspace` for generated binaries/cache; `/tmp` stays small and non-executable, so tools such as Go may need their temporary/cache directories set under `/workspace`. Resource-budget failures are runtime limitations, not evidence of an application defect.

Redaction is conservative and best-effort. Never collect arbitrary credentials in the first place. Local environment names may be inventoried; secret values, personal home/configuration and model tokens must not be supplied to child processes. Unexpected or unsupported runtime features produce precise blockers, not a silent switch of runner.

## Runtime selection and native commands

Static stack schema1 keeps existing fields and adds `environment_names`, name-only `environment_evidence`, and `contracts`. Public audit/workflow reports share these names/citations and inferred configuration resources. Repeated database references with identical source/engine/configuration/service/client/version evidence aggregate into `lines`; existing `line` remains the first citation. Distinct connection names, Compose services, client declarations and conflicting versions remain separate.

Python discovery uses bounded AST inspection (1MiB,20000nodes), never imports or executes project code. Supported stdlib HTTP constructors, WSGI factories and provable socketserver HTTP handlers carry source lines; import comments/generic TCP servers are not HTTP proof. Literal environment reads report names/locations only; defaults are omitted. Dynamic keys, unresolved aliases, shadowing and unsupported syntax remain unknown. This is lexical source evidence, not whole-program or runtime verification.

OpenAPI/Swagger metadata reports declared version and supported method/path operations with source lines, never example/default payloads. JSON supports bounded object structures; YAML supports only conventional two-space block mappings and always reports partial parsing. Tags, anchors/aliases, flow-style paths, duplicate keys and unsupported structures are rejected or marked unsupported/partial. References are not fetched or expanded, and completeness remains unverified. Contract operations are candidates for independent probes, not evidence endpoints work. Installed harness skill directories are excluded from application discovery; harness configuration and project instructions remain eligible inputs.

Discover first. `audit` and `workflow` include a source-cited stack report and runner recommendation; an existing runner is preserved, not replaced automatically. Declared and lock-resolved versions remain different from runtime observations. Missing source evidence and failed external access are different findings. Review the selected runner before executing project code.

The Docker commands above remain an optional constrained disposable backend. They require a trusted local image. Native execution is an explicit choice, NEVER sandboxed: it can access host files/network with the harness user's permissions. Native uses a fresh copy of a registered snapshot and omits ambient credential environment variables; this does not prevent code reading the host. Respect actual harness/project restrictions. No automatic Docker-to-native fallback occurs.

```
python3 <skill>/scripts/initloop.py execute --runner native --timeout 60 /outside/snapshot -- python3 -m unittest
python3 <skill>/scripts/initloop.py baseline /outside/run --runner native
python3 <skill>/scripts/initloop.py verify /outside/run --runner native
```

Native disposable execution is POSIX-only, kills its process group on exit/timeout, bounds captured output and discards its working copy. Daemons escaping their process group and external resources are not isolated or managed; use a constrained runner when these risks matter. It is unsuitable for unknown hostile code. Existing project Compose/native/other runners may instead be executed via the harness under actual permissions; record commands/results without claiming the helper orchestrated those resources.

## Persistent development lifecycle (optional native foreground helper)

Prefer the project's established runner/lifecycle. For an authorized native foreground service that lacks supervision:

```
python3 <skill>/scripts/initloop.py dev start --project /project --ledger /outside/services --name api -- python3 -m app
python3 <skill>/scripts/initloop.py dev status --ledger /outside/services --name api
python3 <skill>/scripts/initloop.py dev logs --ledger /outside/services --name api
python3 <skill>/scripts/initloop.py dev stop --ledger /outside/services --name api
python3 <skill>/scripts/initloop.py dev reset --ledger /outside/services --name api
```

The ledger must be outside source/ancestors and remains private to the controller. The helper records supervisor and child process birth identities before signalling; stop terminates only its owned foreground process group. If the supervisor dies, a surviving independently identified child is `orphaned`: stop can recover it, while reset/restart remain blocked. If ownership cannot be proven (including interruption between process launch and ownership bookkeeping), status is `unknown`, stop sends no unproven signal, and reset/restart remain blocked pending manual inspection of the exact owned resources. Do not clear or fabricate ledger entries to bypass this refusal. Never reuse a name for another project. `INITLOOP_DATA_DIR` points to the owned persistent `data` subdirectory for apps that explicitly use it; other app paths retain their own lifecycle semantics. Start after stop retains this data. Reset is allowed only while stopped and deletes ONLY that directory, not project files or external databases; reseeding is an explicit project command. The helper does not infer arbitrary reset scripts. Preserve named Compose volumes/external services unless separately owned and reset is authorized.

This helper supervises FOREGROUND native processes only. Do not use it for `compose up -d`, daemonizing commands, background launchers or system service management: a stopped launcher is not stopped services. Use the existing runner's lifecycle and exact owned project identity. A slow launch remains owned in `starting` state; duplicate starts and reset remain refused, and stop uses the recorded supervisor. A recorded running process is not application readiness; independently probe business behavior. Persistent logs are private local raw application output (never log credentials); retrieval redacts best effort. Native service execution has host access, not container egress/mount boundaries. Leave requested demos running, publish their exact stop command, and disclose retained resource/data locations.

Shutdown verification must reuse the actual configured endpoint that succeeded before stop, and require owned process termination plus that same listener closed. A stopped launcher, HTTP failure or unused different port is insufficient. For literal shell launch/stop examples and job-control caveats, see [shutdown.md](shutdown.md); named-ledger stop remains the existing foreground-process lifecycle, not a new shell or daemon manager.

Native cleanup proves that the owned group has no live members after termination;
waiting for its leader alone is insufficient. If cleanup remains unresolved, the
named lifecycle keeps its group ownership record and blocks reset/restart. It can
recover a surviving member only when a recorded birth identity still matches;
otherwise inspect the exact `record` path reported by status before manual recovery.
Zombies are excluded from live-member checks because they cannot access the data.

Disposable native commands normally remove their working copy automatically. An
unresolved cleanup instead reports `cleanup: retained`, `outcome: cleanup-pending`
and exit code 125, with exact `retained_work` and `recovery_record` paths. If another
error interrupts execution, the error includes those paths. The private recovery
JSON records the group ID and captured birth identities; it does not authorize a
blind signal to a saved PID/group. Prove ownership and live-group absence before
manually removing that exact retained directory. Unresolved work has no automatic
retention-limit eviction. These controls cover owned foreground process groups;
daemonized or external services remain outside this controller's scope.

## Dependency decision planning

Use [the shared checkpoint](dependency-checkpoint.md) before applying unresolved dependency choices. `checkpoint --help` exposes a persistent planning-only controller, distinct from frozen acceptance runs and workflow proposals. It has no apply operation. The invoking harness supplies inspected capability evidence; its numbered interactive fallback is not a live agent or provider integration test.
