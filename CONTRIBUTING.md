# Contributing

This is an alpha skill with deterministic Python helpers. Keep changes focused, preserve project instructions and data, and state what was actually verified.

Use Python 3.9+ and Git. Run from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=skills/initloop/scripts python3 -m unittest discover -s tests -v
python3 scripts/check_skill.py skills/initloop
python3 scripts/check_publication.py --root . --history
python3 scripts/build_release.py --help
```

Replace initloop with the single skill folder in this repository. Native lifecycle tests require POSIX. Live Docker tests skip unless `INITLOOP_DOCKER_IMAGE` is set to a prepared trusted image; a skipped check is not a pass. CI runs the actual Docker boundary separately.

For behavior changes, preserve a failing test/reproduction before implementation and the passing result afterward. Test useful outcomes rather than generated wording. Never weaken frozen acceptance, project policy or protected tests. Keep full evaluation apps, user source/data, credentials, runtime state and private evaluation notes outside this repository and release assets.

Open a feature branch and pull request. Include the problem, resulting behavior, checks and material limits. Maintainers require passing final-state CI and independent review before merging. Local checks are not remote CI; agent review is not a human GitHub approval. Avoid unrelated refactors or new model/authentication clients.

Report security vulnerabilities privately as described in SECURITY.md. Ordinary bugs and feature requests belong in Issues with a minimal synthetic reproduction and redacted logs.

## Coverage

Coverage is development-only; it is not installed with the skill. In an isolated
Python environment, install `coverage==7.10.7`, then run:

```sh
INITLOOP_DOCKER_IMAGE=python:3.12-alpine python scripts/measure_coverage.py --output "$(mktemp -d)"
```

Prepare the trusted Docker image first, or omit the image variable for native-only
coverage (`--min-statements 85 --min-branches 70`, matching the CI matrix). The full
Docker-enabled suite requires 89% statement and 75% branch coverage. These floors
protect the measured baseline without treating coverage as correctness evidence.
The report includes the runtime package, per-module metrics and Python supervisor
subprocesses through a temporary isolated interpreter startup hook. It excludes
packaging scripts, the launcher shim and Python inside Docker containers. SIGKILL
cannot flush a process's coverage data. JSON, XML and summary reports go to the
new external output directory; prior evidence is never overwritten. CI uploads
these reports for each platform and the Docker-enabled suite. Full synthetic
applications and live agent evaluation remain external; neither percentage gates
nor unit tests certify broad framework or real-provider fidelity.

## Installation maintenance

Installation is project-scoped by default. Use `--agent codex` or `--agent claude-code` to select directly; add `--global` for user scope. The installer normally symlinks a shared copy; use `--copy` for independent copies. Save local edits before replacing an installation.

### Pin, update or remove

After alpha.6 is published, pin its tag instead of tracking the default branch (alpha.5 remains the published release until then):

```sh
npx skills add https://github.com/jwerd/initloop/tree/v0.1.0-alpha.6/skills/initloop --agent codex
```

For unpinned installations:

```sh
npx skills check
npx skills update initloop
npx skills remove initloop
```

Use the same scope as installation (`--global` for user-level). Removal without `--agent` clears the named skill and its agent links in that scope; agent-specific removal can retain the shared copy for other agents. `skills update` tracks the recorded source; to move a pinned installation to a different release, explicitly run `skills add` with that release URL. Keep local edits before updating; editable skill copies are replaced by installer operations.

### Manual fallback

Download the versioned skill ZIP from [Releases](https://github.com/jwerd/initloop/releases), verify its SHA256 against `SHA256SUMS`, and extract it. Copy the complete `initloop` folder—including `LICENSE`, scripts and references—into **one** supported location:

| Agent | Project scope | User scope |
|---|---|---|
| Codex | `.agents/skills/initloop/` | `~/.agents/skills/initloop/` |
| Claude Code | `.claude/skills/initloop/` | `~/.claude/skills/initloop/` |

Do not overwrite an existing skill without saving local edits. No bespoke installer or npm package is needed.
