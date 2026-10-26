# Initloop

**Fill the setup gaps between cloning a repo and running it locally.**

Initloop is an agent skill for discovering how an unfamiliar project runs, repairing missing local dependencies, and leaving behind a useful development runbook. It works with the model already in your coding agent—no model API key, account or separate AI service.

Alpha software. Inspect proposed changes and retain backups; native execution is not a sandbox.

## Install

From the project where you want to use it:

```sh
npx skills add jwerd/initloop
```

Choose **initloop** and your coding agent. Installation is project-scoped by default. To select an agent directly:

```sh
npx skills add jwerd/initloop --skill initloop --agent codex
# Or: --agent claude-code
```

Add `--global` only if you want it available across projects. The installer normally uses symlinks; add `--copy` for independent copies. Don't install both methods/scopes unintentionally.

The external installer currently requires Node.js **22.20+** and Git. Initloop's helpers need Python **3.9+** and Git, with no pip dependencies. Target runtimes and development services depend on the project. Docker is optional; native lifecycle support currently requires POSIX (Linux/macOS).

## Use

In Codex:

```text
$initloop Get this project working locally.
```

In Claude Code:

```text
/initloop Get this project working locally.
```

Start a fresh session if the newly installed skill isn't listed. You can also say “Use the initloop skill to get this project working locally.” If automatic discovery is unavailable, point your agent at the installed `SKILL.md`.

Initloop inspects existing docs, manifests, lockfiles, configuration and runner definitions first. It preserves working native/Compose conventions, identifies missing pieces, proposes isolated repairs, verifies useful behavior and persistence, and reconciles stack/runbook guidance while preserving team policy. It distinguishes an inferred local substitute from a verified external service.

You remain in control of meaningful runner/documentation choices and separately restricted actions. Invoking the skill does not authorize production access, publishing, billing, destructive external resets or deployment.

## Pin, update or remove

Pin the alpha instead of tracking the default branch:

```sh
npx skills add https://github.com/jwerd/initloop/tree/v0.1.0-alpha.1/skills/initloop --agent codex
```

For unpinned installations:

```sh
npx skills check
npx skills update initloop
npx skills remove initloop
```

Use the same scope as installation (`--global` for user-level). Removal without `--agent` clears the named skill and its agent links in that scope; agent-specific removal can retain the shared copy for other agents. `skills update` tracks the recorded source; to move a pinned installation to a different release, explicitly run `skills add` with that release URL. Keep local edits before updating; editable skill copies are replaced by installer operations.

## Manual fallback

Download the versioned skill ZIP from [Releases](https://github.com/jwerd/initloop/releases), verify its SHA256 against `SHA256SUMS`, and extract it. Copy the complete `initloop` folder—including `LICENSE`, scripts and references—into **one** supported location:

| Agent | Project scope | User scope |
|---|---|---|
| Codex | `.agents/skills/initloop/` | `~/.agents/skills/initloop/` |
| Claude Code | `.claude/skills/initloop/` | `~/.claude/skills/initloop/` |

Do not overwrite an existing skill without saving local edits. No bespoke installer or npm package is needed.

## Support and limits

- Bounded static discovery, not universal language/framework coverage. Declared and lock-resolved versions are not runtime observations.
- Native commands have host filesystem/network access. The optional disposable Docker backend constrains its own child, not arbitrary agent tools. Existing project Compose lifecycle can be used; the helper is not a generic Compose orchestrator.
- Verification certifies supplied assertions, not missing proprietary schemas/data/rules. Synthetic databases/APIs are explicitly provisional.
- Instruction-loading and tool availability vary by harness. A copied file or declared MCP entry is not proof of live loading/authentication. See [harness verification notes](skills/initloop/references/harnesses.md).
- No production readiness, provider equivalence or enforced blind-agent isolation claim. See [security](SECURITY.md).

Normal development commands produced for your project work without Initloop. Optional deterministic helpers are documented in [controller reference](skills/initloop/references/controller.md).

## Contribute and build

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=skills/initloop/scripts python3 -m unittest discover -s tests -v
python3 scripts/check_skill.py skills/initloop
python3 scripts/check_publication.py --root . --history
python3 scripts/build_release.py --root . --output dist
```

ZIPs use an explicit source allowlist, stable ordering/timestamps and include MIT attribution. `SHA256SUMS` covers the ZIP and file manifest. Full evaluation applications, private task records and local machine state are not distributed. See [contributing](CONTRIBUTING.md), [changelog](CHANGELOG.md), [source provenance](PROVENANCE.md) and [license](LICENSE).

Installer behavior: [skills CLI reference](https://github.com/vercel-labs/skills/blob/main/docs/commands.md). Harness paths: [Codex skills](https://developers.openai.com/codex/skills), [Claude Code skills](https://code.claude.com/docs/en/skills).
