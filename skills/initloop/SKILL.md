---
name: initloop
description: Discover and repair local onboarding gaps in existing projects using permitted runners and reporting verified flows and blockers. Use for missing setup, inaccessible dependencies, stale runner configuration or agent guidance.
---

# Initloop

Get an existing project usefully running within actual permissions. Preserve its working conventions, user changes and data. Use the invoking harness; never extract credentials or add model API/auth clients. This skill grants no permissions and imposes no universal container/helper/subagent requirement.

## Choose proportionate work

| Request | Path | Evidence to deliver |
| --- | --- | --- |
| Narrow “get working locally” | Discover → existing setup → minimal repair → useful smoke/tests | Short per-flow result, changes, running/stop details and genuine blockers |
| Independent/reusable onboarding, explicit acceptance or required project gates | [Full verification](references/full-verification.md) | Frozen assertions, appropriate isolated/independent checks, project guidance and precise remaining gates |

Treat qualifiers such as “where permitted”, “if available” and “within these controls” as conditions on the requested checks under current capabilities, not an instruction to obtain new permissions. A current pass can finish with an accurately blocked flow; that is a partial result, not full readiness.

Follow stricter project policy and explicit user scope. A full verification request can still yield useful partial progress; an unavailable mechanism is not permission to waive its gate or stop unrelated work. Developing/releasing Initloop itself keeps full regression/review/CI requirements.

1. **Inspect capability and evidence early.** Read supplied harness restrictions, project policy, existing files/runners and declared prerequisites. Use ordinary permitted reads; do not discover permissions through a barrage of denied operations. Follow source/configuration/CI/test references beyond conventional layouts; [discovery.md](references/discovery.md) covers evidence states and meaningful conflicts. When permitted, `audit` and `workflow` provide static clues, not runtime certification. Their exclusions/access findings make coverage partial. Read-only discovery may skip links; snapshot/copy/repair/execution safeguards remain stricter.
2. **Continue with genuinely allowed work.** Prefer existing runners/dependencies and project-local scratch/config/evidence. Establish an observed baseline, make the smallest authorized repair, run ordinary project tests and exercise a useful flow. If helpers, outside paths or fresh agents are unavailable, use distinct permitted mechanisms and state their scope. Do not wrap, rename, copy or otherwise repackage a denied action, broaden permissions, disable controls, fabricate credentials or silently downgrade a chosen isolated runtime. Do not repeat a denial unless its relevant conditions changed. See [restricted onboarding](references/onboarding.md).
3. **Choose the next useful transition before requesting access.** For each unfinished flow, distinguish the required user outcome from conditional or additional evidence, identify its blocking prerequisite, retain the strongest permitted result, and state what accepting a request would newly unlock. Do reachable independent work first. A conditional check outside current permissions stays unexecuted; do not turn its condition into a new access objective. For an unconditional required outcome, request the smallest actual blocking input/access set after preparation; explicit service/demo or full-verification requirements can make transport access indispensable. When only external blockers remain, deliver the scoped partial result and one consolidated next action instead of pursuing every unchecked verification layer. See the decision table in [onboarding.md](references/onboarding.md). Reuse actual decisions/denials, cite only evidenced input names and never expose values.
4. **Verify and report the actual result.** Tests/health200 establish only what they exercise. Mark every important flow **verified**, **unverified** or **blocked**, with commands/source state, observed reason, missing evidenced input names and next action. A login page is not authenticated/business readiness. Do not claim helper certification, real-provider fidelity, enforced isolation or clean independent acceptance without the corresponding executed evidence. Keep failures and precise limits; request full verification when it is a meaningful unresolved scope choice, not a prerequisite to all progress.

For a narrow task, a short report or authorized project-local note is enough; do not demand docs-mode approval or publish a new instruction hierarchy as a setup prerequisite. Reconcile requested shared guidance carefully and preserve existing policy. Default local credentials/config changes to ignored project-local files supported by the runner; never silently edit tracked/shared secrets or env configuration.

Helpers are optional mechanisms: `python3 <this-skill>/scripts/initloop.py --help` (Python3.9+ and Git for static work). Read [controller.md](references/controller.md) when using them, [harnesses.md](references/harnesses.md) for independent contexts, [local-services.md](references/local-services.md) for inaccessible dependencies and [shutdown.md](references/shutdown.md) for owned-process plus exact-listener stop proof. Native execution uses host permissions and is not a sandbox. Keep persistent demos running only when requested; record ownership, logs, retained data and exact scoped stop/reset instructions. Preserve unrelated resources; no broad kills/prunes/resets.

No publishing, billing, production access, external reset, deployment, security bypass or automatic adoption is implied. Never expose credentials/home/Docker sockets for convenience. Actual restrictions and authorization remain authoritative.
