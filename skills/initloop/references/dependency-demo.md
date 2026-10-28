# Interactive dependency checkpoint acceptance demo

Run from the repository root, with Python 3.9+:

```sh
python3 skills/initloop/scripts/demo_checkpoint.py --session /tmp/initloop-dependency-demo
```

Use a new external directory the first time. Rerun the same command to continue. The demo creates only that directory: `sample/fixture.md` contains explicitly synthetic capability facts; `checkpoint/decisions.json` contains actual controller state, findings, choices and events. It starts no services and changes no app/source/configuration. No global installation needed.

This exercises the shipped checkpoint state machine and terminal fallback. The authored investigation callback represents agent-supplied findings, not live-agent inspection or natural-language understanding. Host choice picker integration is specified by the skill and is not exercised here. LDAP, SMTP and reporting are proposed substitutes, not running integrations; there is no executable application fixture and no corporate access. No development login is offered because the fixture provides no such capability.

Try these steps interactively:

1. Enter `1` for LDAP. The investigation explains corporate testing prerequisites. Choose directory `2` (no approved directory) or `3` (**I need something local**), then option `1` for local LDAP/synthetic identities. Corporate integration is blocked in this fixture.
2. Inspect the overview: LDAP is selected, while Email and Reporting remain suggested and unselected. Quit and restart with the same session path to check retention.
3. Enter `2,3` to investigate another two dependencies. Select option `1` separately for each; neither is silently accepted.
4. Revisit LDAP with `1`, directory `3`, and `back` at its option prompt to keep the prior selection. Review with `review` to inspect the combined impacts/access/limits.
5. Use `back`, `cancel`, `resume` and `quit`. Cancel preserves choices and refuses further changes until explicit resume. EOF/Ctrl-C retains state. There is no apply command.

To demonstrate invalidating evidence after selecting Reporting, quit the interactive session and run:

```sh
python3 skills/initloop/scripts/initloop.py checkpoint /tmp/initloop-dependency-demo/checkpoint --action findings --dependency email --finding 'SYNTHETIC new contract requires a different reporting transport' --affected reporting
python3 skills/initloop/scripts/demo_checkpoint.py --session /tmp/initloop-dependency-demo
```

Reporting retains its selection but becomes blocked, and review refuses it until explicit investigation/reselection. In real use, the harness must offer a genuinely compatible option after reinspection; choosing a fixture option here is only exercising that transition.

Inspect `decisions.json` for retained findings and `applied: false`. Application side effects are asserted in automated tests. Cleanup: quit the foreground demo; remove only the exact disposable session directory you created if you no longer need its choices. No server or background process needs stopping. The feature PR remains unmerged until user acceptance; this demo is not a new skill release.
