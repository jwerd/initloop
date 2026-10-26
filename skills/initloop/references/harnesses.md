# Harness integration and verification status

Install/copy this entire skill directory to a project or user skill location supported by your harness, under its normal permissions. Installation is explicit; this repository does not modify global configuration.

- Codex: use its documented skill entry point and native agent tools. Where available, `fork_turns="none"` supplies a minimal task context. Pass only a baseline/verification snapshot, objective, declared prerequisites and bounded budgets. Native subagents may still inherit system/global instructions and broad filesystem tools: absence of conversation history is not proof of filesystem isolation. Use the selected project runner within actual harness permissions; native execution is not sandboxed. A live probe must record actual context/tool behavior before claiming blind execution.
- Claude Code: use its documented `.claude/skills/initloop/SKILL.md` packaging. A skill can run with `context: fork`/an appropriate subagent, but permission and tool behavior must be tested in that installation. No universal frontmatter setting is imposed on Codex by this portable skill. Inspect actual instruction loading, nested `CLAUDE.md` scope and tool permissions independently.

For a fresh agent, send: “Use the Initloop skill at ABSOLUTE_SKILL. Project snapshot: SNAPSHOT. Objective: OBJECTIVE. Base prerequisites: PREREQUISITES. Follow only project setup/instructions visible in this snapshot; do not inspect coordinator state or unrelated files. Discover and preserve the project runner; execute within actual permissions. Native host execution is not sandboxed. Use a bounded, proportionate time/tool budget; report overruns. Report attempts, exit states, inferred missing steps and verified outcomes.”

Prompt instructions alone do not constrain arbitrary tools. If the harness cannot restrict project tool routes or snapshot visibility, describe the run as an independent-context assisted evaluation, not an enforced blind sandbox. Manual separate sessions are an option only when the user/harness can establish the required boundary. Never access harness credentials or start headless model clients without explicit supported integration/authorization.

Helper unit tests and deterministic CI can run without a model. Live harness tests consume the existing allowance, and unavailable usage/cost telemetry must be reported as unknown. A skill does not confer new provider quotas, model selection or unattended CI inference.

Official references checked during implementation:
- https://developers.openai.com/codex/skills
- https://learn.chatgpt.com/docs/agent-configuration/subagents
- https://code.claude.com/docs/en/skills

The implementation evidence report records which harness paths were actually exercised. Documentation compatibility is not live verification.
