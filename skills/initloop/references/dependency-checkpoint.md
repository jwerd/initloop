# Shared dependency decisions

This is a skill workflow in the invoking terminal/agent harness. It does not require a web UI, TUI framework, model client or external service. Use it after discovery reveals meaningful choices and before applying dependency setup. Narrow tasks with no unresolved dependency choice need no ceremony.

## Discover, then choose together

Inspect project policy, existing runners, source/configuration consumers, supported endpoint overrides, contracts and current harness capabilities using permitted reads. Static helper inventory is a clue, not complete capability discovery. Batch independent reads; do not ask users to locate facts already available. Distinguish observed source facts, inferred options, user decisions, access blockers and runtime verification. Never claim corporate access or work-app inspection from a synthetic fixture.

Build a concise overview with a stable ID per dependency, current selection (initially none), suggested default, and **suggested / selected / blocked** status. A suggestion is not consent. Display blockers alongside the retained selection. Include identity, mail, reporting and other actual dependencies, with evidence-based recommendations for each.

**The first/default recommended action is “Accept recommendations and review.”** If explicit selections already exist, label it “Keep selections, accept remaining recommendations and review.” This single explicit action selects all currently supported remaining suggestions and proceeds directly to combined review; investigation and individual edits are optional, not mandatory onboarding steps. Preserve existing explicit choices. Before presenting this action, check recommendations against retained choices and findings; mark incompatible or stale decisions blocked rather than silently accepting conflicts. Accept valid remaining suggestions even if other decisions are unresolved, then surface only the actual unresolved decisions. Never invent defaults.

Use the host choice picker when available. Put the recommended acceptance action first and preselect it where supported, but require the user to submit it explicitly. Never treat silence, blank input, continuation or a choice to investigate as acceptance. Accepting recommendations is not permission to apply setup. A picker accepting only one answer can include “investigate several” followed by a multi-selection step or numbered list. Fallback example:

```
0 Accept recommendations and review (Recommended)
1 LDAP login      suggested: local LDAP     selected: —
2 Email delivery  suggested: local capture  selected: —
3 Reporting API   suggested: local fixture  selected: —
Choose 0 to accept; optionally investigate 1 / 2 / 3 / several (e.g. 1,3); revisit; review; back; cancel
```

Investigate only the requested dependencies, allowing multiple investigations before returning. Explain each option's evidence, configuration/service impact, required access, unsupported capabilities and remaining verification. Record findings, explicit choices and blockers; return to the same overview with unrelated suggestions unselected. Never apply setup during investigation. A choice to investigate is not a selection. Let the user revisit a selected dependency without losing its current choice.

For directory access, include **“I need something local”** alongside approved development access and no approved directory. If corporate testing is requested, identify the actual missing approved development endpoint, scoped credentials and network access; do not ask for production access. With no approved directory, offer local LDAP with synthetic identities only where the inspected consumer supports an applicable configuration path. It exercises LDAP paths and is **not proof of corporate compatibility**. Call out unknown schema, TLS, bind/search, group mapping and policy behavior. No generic LDAP adapter is guaranteed. If no applicable configuration exists, keep the flow blocked and report the limitation.

**Never edit the target application's source to bypass authentication.** Offer an existing development login only when evidence shows the app already supports it through configuration; name its limits and access impact. Missing evidence means that option is unavailable, not a task to invent a bypass. Local services and config overrides must respect actual permissions, egress controls and service ownership; proposing them does not launch them.

## Retain, revisit, review

Use existing project-local authorized planning notes or private controller state outside source. Do not put secrets in decisions, findings or catalogs. On ordinary continuation, load previous choices/findings before asking again. Preserve denied access decisions. If source, harness capabilities or new findings invalidate a choice, mark the affected decision blocked and show why, keeping the previous selection visible. Do not silently overwrite it. Resolve the affected choice explicitly; source drift needs reinspection and explicit catalog revision. Use `revise --catalog` after reinspection to update options/evidence with the same dependency IDs. Findings and choices survive; affected selections become blocked until explicit reconfirmation. Changed dependency scope requires a fresh checkpoint with prior findings/choices as context.

Before setup, review **all** selected dependencies together: impacts, shared constraints, required access, unsupported behavior, remaining checks and actual setup actions. Resolve cross-dependency conflicts and unselected/blocked decisions first. Back returns to the overview with decisions intact. Cancel stops planning without applying setup and retains state for explicit resume. Review is not an apply authorization: obtain any still-required service/configuration permission with this concrete combined plan, then use existing setup/repair mechanisms. Explicit acceptance may select supported recommendations together; it never applies setup. Review still requires every decision to be resolved. Recheck actual permissions/provider changes at execution; source hashes cannot detect those changes.

## Optional deterministic controller

`checkpoint` stores a separate `decisions.json` using the helper's atomic private-file write pattern. It is planning data, not acceptance evidence; never insert it into a frozen verification contract or confuse it with `Run` execution phases. The controller offers **no apply action**, does not execute app code, and does not discover/verify capabilities itself. The invoking harness supplies a source-cited catalog and findings after inspecting actual context. It cannot prove that supplied citations are true. Treat state as trusted controller data, use one writer, and reload stale instances. Host picker presentation is the harness's responsibility.

```
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action create --project /project --catalog /outside/catalog.json
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action accept
# Optional investigation or individual changes instead:
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action investigate --dependency ldap --dependency email
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action findings --dependency ldap --finding 'Cited finding; no secrets' --affected reporting
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action select --dependency ldap --option local
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action interactive
python3 <skill>/scripts/initloop.py checkpoint /outside/decisions --action review
```

`--action accept` is explicit bulk acceptance and opens combined review if every decision is resolved. It preserves previous explicit choices, blocked/stale selections and findings. Supported remaining suggestions are accepted even when others remain unresolved; the returned overview identifies those blockers. No investigation is required first. The interactive fallback shows this as action `0` (or `accept`); blank input makes no choice.

`show` (default), `back`, `cancel` and `resume` also work in separate invocations. `--affected` preserves but blocks another selection; explicit reselection acknowledges the finding. Option `blocked` gives a reason that prevents selection (e.g. no approved directory). To change capability availability, reinspect and use `--action revise --catalog /outside/revised.json`; do not edit controller JSON. Every catalog dependency requires `id`, `label`, nonempty `evidence`, and an `options` list (possibly empty if no supported options are known). `suggested` may name an evidenced option or be omitted/null when no recommendation is supported. Each option requires `id`, `label`, nonempty `evidence`, `impact`, `access`, `unsupported`, `verification`, and optionally a nonempty `blocked` reason. Use concise nonsecret text and stable IDs. Suggestions can reference blocked options, but those remain unresolved and cannot be selected or bulk-accepted. Missing recommendations stay unresolved instead of taking the first option automatically. Catalog revision can add a supported recommendation without discarding choices/findings; conflict blockers still need explicit resolution.

Combined review compares included source content and scan findings with discovery. Drift blocks all decisions while retaining choices and requires catalog reinspection/revision and explicit reconfirmation. This conservatively detects included changes, not external provider drift or complete source coverage; partial discovery stays explicit in state. Cancel/back/quit never change the application. The fallback prints current evidence and options; it does not interpret natural language or perform a live investigation. The agent can instead use machine-readable actions with the host picker and its own investigation tools.
