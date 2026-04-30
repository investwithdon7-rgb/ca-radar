# Contributing to ca-radar

Thank you for helping make Conditional Access tooling better for everyone.

## Getting started

```bash
git clone https://github.com/tekdruid/ca-radar
cd ca-radar
uv sync --extra dev
uv run pytest
```

## Adding a new detection

Each detection lives in a single file under `ca_radar/analysers/packs/<category>/`.

1. Create `ca_radar/analysers/packs/<category>/<your_check>.py`
2. Subclass `Analyser` from `ca_radar.analysers.base`
3. Return `list[Finding]` from `analyse(snapshot, resolver)`
4. Add a test in `tests/analysers/test_<your_check>.py` using fixtures from `tests/fixtures/`
5. Every finding must include: `id`, `severity`, `evidence`, `affected_principals`, and at least one `remediation` snippet

New detections should never require changes to the renderer.

## Code style

- Lint: `uv run ruff check .`
- Format: `uv run ruff format .`
- Type check: `uv run mypy ca_radar`
- Tests: `uv run pytest`

All four must pass before opening a PR.

## Snapshot schema changes

The snapshot is a public API. If you change `ca_radar/snapshot/models.py`, bump the snapshot schema version in `ca_radar/snapshot/store.py` and document the change in `CHANGELOG.md`.

## Pull request checklist

- [ ] Lint and type checks pass
- [ ] Tests pass with coverage > 80% on changed files
- [ ] New detection maps to at least one SCuBA or CIS baseline control
- [ ] No write scopes added anywhere

## Licence

By contributing you agree your changes are released under the project's MIT licence.
