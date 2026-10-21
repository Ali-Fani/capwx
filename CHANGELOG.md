# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - Unreleased

First release. Pre-release until a `v0.1.0` tag is published to PyPI.

### Added

- Format-2 Cap protocol server: `create_challenge`, `redeem` and their async twins, for the
  `hashwx`, `sha256-pow` and `instrumentation` protocols. Compatible with `capjs-core` 0.1.5 (verified
  in both directions by the `node` test suite).
- Verification tokens: `validate_token`, `siteverify` and async twins. Stored tokens (single use with a
  store) and stateless tokens (valid until expiry).
- Stores: `MemoryStore` (development), `DjangoCacheStore`, `RedisStore` and `AsyncRedisStore`.
- Instrumentation: a generated probe script and a verifier, with automation detection and risk flags.
- Django integration (`capwx.contrib.django`): settings with per-site overrides, endpoints under a
  URL prefix of your choice, `{% capwx_scripts %}` and `{% capwx_widget %}` template tags,
  `CapField`, `@require_cap`, CSRF modes, `BEFORE_CHALLENGE_HOOK` and `DIFFICULTY_HOOK`, and the
  `capwx_check` management command.
- Django Ninja integration (`capwx.contrib.ninja`): `build_router`, `install` and `CapRequired`.
- Vendored assets: the server `hashwx.wasm` (LGPL-3.0, separate file) and the browser assets, each
  with a pinned SHA-256 and `VERSIONS.json`. See [UPSTREAM.md](UPSTREAM.md).
- Documentation: README, [SECURITY.md](SECURITY.md), [UPSTREAM.md](UPSTREAM.md) and
  [docs/security-checklist.md](docs/security-checklist.md).

### Security

- `repr()` of `CapConfig` and of the Django site configuration no longer shows the secrets.
- `DjangoCacheStore.take` is atomic where `cache.add` is atomic (Redis, Memcached, locmem), so a
  verification token cannot be consumed twice by two concurrent requests. Previously it was a
  get-then-delete.
- `hashwx` and `sha256-pow` verification bound the difficulty they accept, as minting does. An empty
  `sha256-pow` target matched every nonce.
- `CapRequired(field="")` accepts only the header, as documented. An empty JSON key was accepted before.
- A `DIFFICULTY_HOOK` or `BEFORE_CHALLENGE_HOOK` dotted path that cannot be imported is reported as
  `ImproperlyConfigured`, not as a bare `ImportError`.
