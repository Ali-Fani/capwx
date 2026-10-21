# capwx: project guidelines

Unofficial Python server for the Cap CAPTCHA widget (HashWX, instrumentation). Pure Python, one universal
wheel. The design record is `capwx.plan.md`; upstream pins are in `UPSTREAM.md`.

## Commands (always through uv)

```bash
uv sync --group dev --group e2e --extra django --extra ninja --extra drf --extra bolt
uv run pytest -q                      # unit suite (default)
uv run pytest -m node -q              # interop with capjs-core (installs into a pytest temp dir)
uv run pytest -m e2e tests/e2e -q     # real-browser tests (needs Playwright/Chrome)
uv run ruff check . && uv run ruff format --check .
uv run pyright                        # strict on src/capwx
uv build && uv run python scripts/check_dist.py
```

## Rules

- **Never run `npm`/`npx` outside a directory with its own `package.json`.** It walks up and rewrites
  the user's home `node_modules` (this happened once). The node tests install into a pytest temp dir.
- Client input never raises: functions return results with a `Reason`. Only misconfiguration raises
  `CapwxError`.
- Never log tokens, nonces, solutions or instrumentation probe data.
- The HashWX wasm is LGPL-3.0 and stays a separate, replaceable file. Do not port HashWX's C code to
  Python. Keep `third_party/hashwx` (sdist only) and the source offer in `NOTICE` current.
- Keep `import capwx` free of `wasmtime`; it is imported lazily and is optional off x86-64/ARM64.
- Upstream (`capjs-core` and the widget bundle) wins over the plan when they disagree; report it.
- Vendored assets are pinned and hash-checked. Update them only through `scripts/vendor_assets.py`.
- ruff also formats Python code blocks in Markdown: keep README/docs snippets valid, formatted Python.

## Release checklist (do ALL of it before tagging; a published PyPI version can never be edited)

PyPI builds the project page from the README at the tagged commit, so stale docs are stuck on that
version forever. `tests/test_release_consistency.py` enforces most of this; it must pass.

1. Pick the version. Update it in **both** `pyproject.toml` and `src/capwx/__init__.py`
   (`tests/test_challenge.py` also asserts `__version__`), then `uv lock`.
2. `CHANGELOG.md`: turn `[Unreleased]` into `## [X.Y.Z] - YYYY-MM-DD`; list Added/Changed/Fixed.
3. Search for stale version text: `grep -rnIi "0\.[0-9]\.[0-9]\|pre-release\|unreleased\|not on PyPI"`
   over `README.md`, `SECURITY.md`, `docs/`, `NOTICE`, `UPSTREAM.md`. Fix the README status line, the
   "Known limitations" section and the `SECURITY.md` supported-versions table.
4. Remove old artifacts from `dist/`, then `uv build` and `uv run python scripts/check_dist.py`.
5. Run every gate: unit, `-m node`, `-m e2e`, ruff, pyright. Push and wait for CI to be green.
6. Only then tag: `git tag -a vX.Y.Z -m "capwx X.Y.Z" && git push origin vX.Y.Z`. The Release workflow
   checks the tag equals the package version, then waits for the `pypi` environment approval
   (Trusted Publishing: owner `Ali-Fani`, repo `capwx`, workflow `release.yml`, environment `pypi`).
7. After approval, confirm the version on PyPI and `pip install capwx==X.Y.Z` in a clean venv.
8. Never tag, publish, or change repository visibility without the maintainer's explicit go-ahead.
