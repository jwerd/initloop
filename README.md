# Initloop

### Clone the repo. Close the gaps. Get it running.

Missing setup steps. An unreachable database. No seed data. An API you can’t access.
**Initloop turns those blockers into a working local dev environment.**

It’s a skill for your coding agent: discover what the project needs, repair the gaps,
and prove the useful workflow works. A fresh setup attempt reveals the missing pieces;
failed checks feed the next repair. It uses the model you already have.

![Initloop: inspect the repo, fill the gaps, run real workflows, and repeat until the app works locally.](assets/initloop-loop.svg)

**You get:** local services and synthetic data where needed, repeatable dev commands,
and a runbook grounded in what actually passed. Working native and Compose conventions stay in place.

## Get started

From your project:

```sh
npx skills add jwerd/initloop
```

Choose your agent, then ask:

```text
$initloop Get this project working locally.
```

Use `/initloop` in Claude Code. Start a fresh session if the skill isn’t listed.
No extra model API key or AI service to configure.

## Built for the next developer, too

Initloop checks setup, useful requests, persistence and the change/test cycle.
It leaves linked **AGENTS.md / CLAUDE.md, a stack reference and a development runbook**
so the next session can pick up where you left off.

If a private schema or contract can’t be established, it reports the gap and labels
any local substitute as provisional.

---

**Alpha.** Installer: Node22.20+ and Git. Helpers: Python3.9+ and Git. Docker is optional;
native lifecycle requires Linux/macOS and runs with host permissions.

[Install options, pinning & updates](CONTRIBUTING.md#installation-maintenance) ·
[Releases](https://github.com/jwerd/initloop/releases) ·
[Helper reference](skills/initloop/references/controller.md) ·
[Harness support](skills/initloop/references/harnesses.md) ·
[Security](SECURITY.md) · [Contribute](CONTRIBUTING.md) · [MIT](LICENSE)
