# Contributing

Thank you for considering a contribution to ca-radar!

## Development setup

```bash
git clone https://github.com/tekdruid/ca-radar.git
cd ca-radar
uv sync --extra dev
```

## Running tests

```bash
uv run pytest --ignore=tests/e2e
```

## Adding a new analyser

1. Create `ca_radar/analysers/packs/<category>/<name>.py`
2. Subclass `Analyser`, implement `finding_ids` and `analyse()`
3. Register in `ca_radar/analysers/runner.py` `_default_analysers()`
4. Add `finding_ids` → framework control mappings in `ca_radar/baselines/data/scuba.yaml` (if applicable)
5. Write tests in `tests/analysers/test_<name>.py`
6. Add the finding IDs to the [Findings Reference](findings-reference.md)

## Adding a baseline framework

Drop a YAML file in `ca_radar/baselines/data/`. See [Baseline Alignment](baseline-alignment.md) for the schema.

## Code style

```bash
uv run ruff check .
uv run ruff format .
```

## Pull request checklist

- [ ] Tests pass (`uv run pytest --ignore=tests/e2e`)
- [ ] New code has test coverage
- [ ] Finding IDs are stable (never rename existing IDs)
- [ ] `CHANGELOG.md` entry added
