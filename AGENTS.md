# Backend agent instructions

These instructions extend the workspace-level `../AGENTS.md` for the `yeti`
repository.

## Project map

- `core/web`: FastAPI application and HTTP API.
- `core/schemas`: domain schemas and ArangoDB-backed models.
- `core/events`: event consumers.
- `core/migrations`: persistence migrations.
- `plugins`: feeds, analytics, events, exports, and inline extensions.
- `yetictl`: command-line tooling.
- `tests`: schema, API v2, and core tests.

Find and follow an existing implementation in the relevant area. Do not edit
`private` extension directories or generated/archive data unless the task names
them explicitly.

## Toolchain and commands

Use Python 3.13 and `uv`; `uv.lock`, `pyproject.toml`, and CI are authoritative.
Do not introduce Poetry commands.

- Install: `uv sync --group dev`
- Install optional plugin dependencies: `uv sync --all-groups`
- Lint: `uv run --no-sync ruff check .`
- Format check: `uv run --no-sync ruff format . --check`
- Type check: `uv run ty check --exit-zero-on-warning`
- Focused test: `YETI_TESTING=true uv run pytest <test-path>`
- Full local test wrapper: `make -C .. test-backend`

Run focused tests while iterating, then the affected configured suites. Plugin
type checking is a separate CI job because it requires all dependency groups;
follow `.github/workflows/typecheck.yml` for its exact scope.

The workspace test wrapper supplies the same auth and system settings as
`.github/workflows/unittests.yml`, together with host-local service addresses
and writable artifact paths. Outside that workspace, reproduce the workflow's
environment before invoking pytest; a bare test command can otherwise inherit
the container-oriented `/opt/yeti` paths from `yeti.conf.sample`.

## Backend boundaries

- Tests must set `YETI_TESTING=true` or explicitly connect to `yeti_test`.
  Database fixtures truncate collections; never point them at non-test data.
- Ask before changing database schemas, migrations, authentication semantics,
  permission behavior, or public API contracts.
- Preserve FastAPI/Pydantic response shapes. When the OpenAPI contract changes,
  coordinate regeneration of the frontend schema.
- Feeds and third-party integrations can perform network requests. Use fixtures
  or mocks unless live access is explicitly requested.
- Keep Ruff and `ty` ratchets at least as strict as they are now. Do not suppress
  new diagnostics broadly to make a check pass.
