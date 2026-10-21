# Security checklist (plan §15)

Review for the 0.1.0 release, re-checked for 0.2.0. Each §15 item is checked against the code and the tests. Paths are
relative to the repository root. "Fixed" means the review found a gap, the code changed, and a test
now pins the fix.

## §15 items

| # | Item | Result | Evidence (code) | Evidence (tests) |
|---|---|---|---|---|
| 1 | Secret of at least 16 bytes enforced; 32+ random bytes recommended | Pass | `src/capwx/config.py` `MIN_SECRET_BYTES = 16` and `_check_secret`; `src/capwx/contrib/django/conf.py` `_build` requires `SECRET`. The recommendation is in the README, SECURITY.md and the `SECRET` error message. | `tests/test_config.py` (`test_secret_exactly_16_bytes_ok`, `test_short_secret_rejected`, `test_secret_length_counts_utf8_bytes`); `tests/test_django.py::test_short_secret_is_improperly_configured` |
| 2 | Every secret or token comparison uses `hmac.compare_digest` | Pass | `src/capwx/_crypto.py` `jwt_verify` (signature check); `src/capwx/tokens.py` `_check_site_secret` (siteverify secret). A grep for `==`, `!=` and `in` over secret and token names finds no other comparison of secret material. Stored tokens are looked up by key, and the key is `sha256(secret_part)` (`tokens.py` `_store_key`), so no secret is compared directly. | `tests/test_crypto.py` (tampered signatures), `tests/test_tokens.py::test_siteverify_wrong_secret_does_not_consume`, `test_siteverify_bytes_secret` |
| 3 | Client input never raises; bodies size-limited; JSON depth irrelevant | Pass | `src/capwx/challenge.py` `_verify_body` and `redeem` return a reason for every malformed field. `hashwx.verify`, `sha256_pow.verify` and `protocols/instrumentation/verify.py` `verify` are documented as never raising, and the first two wrap their body in `try`. `src/capwx/contrib/django/views.py` `_parse_json` catches `RecursionError`, so depth cannot crash a request. `_read_body` rejects bodies over `MAX_BODY_BYTES` (64 KiB) by header and by bytes read. Only fixed keys are read from the JSON. | `tests/test_django.py::test_oversized_body_is_413_by_content_length`, `test_oversized_body_is_413_when_header_is_missing`; `tests/test_security_checks.py::test_hostile_client_solutions_never_raise`; `tests/test_error_paths.py` (body reading, malformed claims) |
| 4 | Replay claim happens after verification; nonce key derived from the JWT signature | Pass | `src/capwx/challenge.py` `redeem` and `aredeem` claim the nonce only after `_verify_body` has accepted every solution. The key is `_NONCE_KEY_PREFIX + jwt_sig_hex(token)` (`_verify_body`). Residual: the claim is optional, see "Residual risks". | `tests/test_challenge.py::test_nonce_is_claimed_only_after_all_verification`, `test_wrong_solution_does_not_burn_the_replay_claim`, `test_nonce_key_and_ttl_are_derived_from_token_signature`, `test_replay_of_same_body_is_already_redeemed` |
| 5 | Verification tokens are single use (`take` gets and deletes) when a store is configured | Pass, after a fix (see F1) | `src/capwx/tokens.py` `validate_token` and `avalidate_token` consume through `TokenStore.take`. `MemoryStore.take` holds a lock. `RedisStore.take` uses `GETDEL`, or a `MULTI` transaction. `DjangoCacheStore.take` was not atomic; it now wins with an atomic `cache.add` marker. | `tests/test_tokens.py` (consume and replay tests); `tests/test_security_checks.py::test_a_verification_token_is_consumed_by_exactly_one_caller_under_a_race`; `tests/test_stores.py` |
| 6 | Only token hashes are stored | Pass | `src/capwx/tokens.py` `_store_key` keys on `sha256_hex(secret_part)`. The stored value is the expiry time only, never the token. | `tests/test_tokens.py::test_issue_stored_only_stores_hash` |
| 7 | No tokens, nonces, solutions or probe data in logs | Pass | The logging calls in `src/capwx/` are: `challenge.py` `_finish` (site, success, reason, duration), the event-callback failure and the no-nonce-store warning; `contrib/django/views.py` (CSRF failure logs `request.path`, body-size rejection, a blocked challenge that logs no hook message); `obfuscate.py` (clamp warning). None logs a token, nonce, solution or probe value. | `tests/test_challenge.py::test_one_info_line_per_redeem_without_tokens_or_solutions` |
| 8 | Vendored wasm hash verified at load | Pass for the vendored wasm. Not applicable to a replacement (see R3). | `src/capwx/protocols/hashwx.py` `_load_wasm_bytes` compares SHA-256 with `_vendor/hashwx/SHA256` before compiling. `capwx_check` checks the browser copy as well. `scripts/check_dist.py` checks the built artefacts. | `tests/test_hashwx.py::test_vendored_wasm_tamper_is_rejected`, `test_vendored_wasm_untampered_loads`; `tests/test_django.py` (`capwx_check`) |
| 9 | The `x` (extra) claim is documented as client-readable | Pass | `src/capwx/challenge.py` `create_challenge` docstring says the client can read it. The README and SECURITY.md say so too. The token is a JWT, so the payload is base64, not encrypted. | `tests/test_challenge.py::test_token_payload_has_scope_extra_and_timestamps`, `test_extra_must_be_dict_and_scope_is_optional` |
| 10 | Difficulty bounds enforced on both mint and verify (`d`, `n`) | Pass, after additions (see F4, F5) | Mint: `src/capwx/config.py` `CapConfig.__post_init__` bounds `hashwx_difficulty` (1 to 1 000 000 000), `hashwx_nonces_per_hash` (1 to 1 048 576) and `sha256_difficulty` (1 to 16). Verify: `src/capwx/protocols/hashwx.py` `verify` checks `n` in `[1, MAX_NONCES_PER_HASH]` and `d` in `[1, MAX_HASHWX_DIFFICULTY]` before any wasm call; `src/capwx/protocols/sha256_pow.py` `verify` requires the target to be 1 to 16 hex digits. | `tests/test_security_checks.py` (`test_sha256_verify_refuses_an_empty_or_oversized_target`, `test_hashwx_verify_bounds_difficulty_before_evaluating`, `test_hashwx_mint_difficulty_range_matches_verify_bound`); `tests/test_hashwx.py`; `tests/test_sha256_pow.py` |

## Gaps found in this review

| # | Finding | Fix | Test |
|---|---|---|---|
| F1 | `DjangoCacheStore.take` was a get followed by a delete. Two concurrent redeems of one verification token could both succeed. | `take` wins with an atomic `cache.add` of `<key>:consumed`, which lives as long as the token. Holds where `add` is atomic: Redis, Memcached, locmem. | `test_a_verification_token_is_consumed_by_exactly_one_caller_under_a_race` (fails on the old code: both calls return the expiry). |
| F2 | `repr(CapConfig)` and `repr(SiteConf)` included the secret, which would reach any traceback or debug print. | `secret` and `site_secret` are `field(repr=False)`. | `test_config_repr_never_contains_the_secret`, `test_site_conf_repr_never_contains_the_site_secret` |
| F3 | `CapRequired(field="")` documents header-only tokens, but a JSON body with an empty key was accepted. | `extract_token` returns `None` for an empty field name, after the header check. | `test_an_empty_field_name_disables_the_body_lookup` |
| F4 | `sha256_pow.verify` accepted any target. An empty target is a prefix of every digest, so every nonce verified. Upstream data cannot reach this (the expectations are authenticated), but the verifier should not rely on that. | Target must be 1 to 16 hex digits (the `sha256_difficulty` range). | `test_sha256_verify_refuses_an_empty_or_oversized_target`, `test_sha256_verify_still_accepts_a_correct_solution` |
| F5 | `hashwx.verify` accepted any `d`. Upstream does not bound it, and the expectations are authenticated, so this is defence in depth. | `d` must be at most `MAX_HASHWX_DIFFICULTY = 1 000 000 000`, the top of the mint range, checked before the wasm runs. The node interop suite still passes. | `test_hashwx_verify_bounds_difficulty_before_evaluating` |
| F6 | Bad dotted paths in `DIFFICULTY_HOOK` and `BEFORE_CHALLENGE_HOOK` raised a bare `ImportError` at first request, not `ImproperlyConfigured`. | Wrapped as `ImproperlyConfigured`. | `tests/test_settings_and_command.py` (`DIFFICULTY_HOOK` cases) |
| F7 | Hostile client bodies had no regression test. | Added. | `test_hostile_client_solutions_never_raise` |

## Residual risks (documented, not changed)

| # | Risk | Why it stays | Where it is documented |
|---|---|---|---|
| R1 | Stateless tokens (no token store) can be replayed until `token_ttl_ms` expires. | A design choice for setups without a store. `validate_token` refuses them when a store is passed. | README "Security notes", `tokens.py` docstring |
| R2 | Without a `nonce_store`, a solved challenge can be redeemed repeatedly until it expires. | Optional by API design. A warning is logged once. | README, `challenge.py` `_warn_no_nonce_store` |
| R3 | `hashwx_wasm_path` loads the file without a hash check. | The override exists so that users can replace the LGPL wasm with their own build. | README "Licence", `UPSTREAM.md` |
| R4 | `DjangoCacheStore` is not single use on the database cache backend, where `add` is not atomic. | Django offers no atomic get-and-delete. | README "Stores", module docstring |
| R5 | No rate limiting in capwx. | Belongs to the application or its proxy. | README "Security notes" |
| R6 | The instrumentation probe is a heuristic, not a security boundary. The expected values come from the same program the client runs (the init values and the operations are in the generated script, and the blob is deflate and base64, not encryption), so they are not secret. The `==` comparison in `verify.py` is an integrity check, not a credential check. | Browser automation cannot be detected reliably. `block_automated_browsers` raises the cost only. | README "Security notes", `verify.py` docstring |
| R7 | Browser assets under `static/capwx/` are not hash-checked at request time. | They are checked at build (`scripts/check_dist.py`) and by `capwx_check`. | `UPSTREAM.md` |
| R8 | The instrumentation verifier is trusted not to raise (challenge.py does not wrap it). | Its docstring makes that promise, and the hostile-input test covers the common shapes. | `protocols/instrumentation/verify.py` docstring |

## CSRF

- `CSRF_EXEMPT: True` (default): the endpoints read no session or cookie, and a verification token is
  only useful when the CSRF-protected form submits it. Tests:
  `tests/test_django.py::test_csrf_exempt_true_allows_post_without_token`.
- `CSRF_EXEMPT: False`: `contrib/django/views.py` `_csrf_gate` runs Django's CSRF check on every
  request, and `{% capwx_scripts %}` installs the `X-CSRFToken` fetch hook. Tests:
  `test_csrf_exempt_false_enforces_csrf_on_every_endpoint`, `test_scripts_tag_installs_csrf_fetch_when_not_exempt`.

## Verification run (M13 final)

| Check | Result |
|---|---|
| `ruff check .` | All checks passed |
| `ruff format --check .` | 74 files already formatted |
| `pyright` (strict, `src/capwx`) | 0 errors, 0 warnings |
| `pytest` (default suite) | 1390 passed, 9 skipped (Redis tests: no `redis` package and no `REDIS_URL`), 18 deselected (e2e and node) |
| Coverage on `src/capwx` (branch) | 98% total; gate is 90% (`fail_under`) |
| `pytest -m node` | 11 passed (Python and capjs-core 0.1.5 in both directions) |
| `pytest -m e2e tests/e2e` | 7 passed (Playwright's bundled Chromium) |
| `uv build` and `scripts/check_dist.py` | Wheel and sdist contain every required file; hashes match |
| Fresh venv from the wheel | `import capwx`, `hashwx_ready()`, the official HashWX vector, and a mint, redeem, single-use round trip all pass |
