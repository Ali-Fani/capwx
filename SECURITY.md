# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report them privately to: **alifani1377@gmail.com**.

Include the affected version, a description of the issue, and steps to
reproduce. We aim to acknowledge reports within 5 working days.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (unreleased) | Yes, once released |

## Handling secrets

- Never log tokens, nonces, solutions, or instrumentation probe data. capwx logs one INFO line per
  redeem with the site, success, reason and duration only.
- Use a secret of at least 16 bytes; 32 or more random bytes from the
  environment is recommended. capwx refuses shorter secrets.
- The secret is never part of `repr()` for `CapConfig` or a Django site configuration.
- Verification tokens are single-use only when a token store is configured.
  Without a store, a stateless token can be replayed until `token_ttl_ms` expires.
- Use a shared store in production (`RedisStore`, or a Django cache backend with an atomic `add`).
  `MemoryStore` is for development and tests only.
- The `x` (extra) claim of a challenge token is readable by the client. Do not put secrets in it.

The full review against the §15 checklist is in [docs/security-checklist.md](docs/security-checklist.md).
