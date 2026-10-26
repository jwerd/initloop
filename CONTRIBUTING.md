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
