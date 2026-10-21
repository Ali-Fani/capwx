# Licence review brief: LGPL-3.0 `hashwx.wasm` inside an Apache-2.0 package

Status: **prepared for review, not reviewed.** This is an engineering summary of
the facts, not legal advice. Get a licence review before relying on it.

## Facts

| Item | Detail |
|---|---|
| capwx code | Apache-2.0 (`LICENSE`), includes a Python port of Cap's `capjs-core` (also Apache-2.0) |
| HashWX | tevador/hashwx, LGPL-3.0, commit `74b567a31276a4c5d7cb232a5b7639467f49f961` |
| Form shipped | A prebuilt WebAssembly binary (`hashwx.wasm`, 12 541 bytes, sha256 in `src/capwx/_vendor/hashwx/SHA256`), taken unmodified from Cap's `core/vendor/` |
| Where it ships | `capwx/_vendor/hashwx/hashwx.wasm` (server, run with wasmtime) and `capwx/contrib/django/static/capwx/hashwx.wasm` (browser, from `@cap.js/wasm` 0.0.8; byte-identical) |
| Separation | Separate files, never linked into Python code; loaded at runtime from a path; replaceable via `CapConfig.hashwx_wasm_path` (server) and by overriding the static file (browser) |
| Not done | HashWX's C code is **not** ported to Python, so no capwx module is LGPL |
| Licence text | Shipped beside both copies and listed in `license-files` |

## Obligations to check (LGPL-3.0 §4 and §5, combined/conveyed works)

1. Prominent notice that HashWX is used and covered by the LGPL, plus a copy of
   the licence: **done** (`NOTICE`, README, licence files beside the binaries).
2. Allow modification of the library and reverse engineering for debugging such
   modifications: nothing in capwx forbids this; the Apache licence does not
   restrict it. **Reviewer: confirm.**
3. Provide the Corresponding Source for the binary, or a written offer, or a
   pointer to it (§4/§6). **Gap, see below.**
4. Provide a way to relink/replace the library with a modified version (§4(d)):
   `hashwx_wasm_path` and the static-file override. Note that the server-side
   path is *not* hash-checked, deliberately, so a replacement is accepted.
   **Reviewer: confirm this meets "suitable shared library mechanism".**

## Known gaps

- **Build recipe unknown.** Upstream Cap vendors the binary and records only the
  HashWX commit (`core/vendor/hashwx-COMMIT.txt`); it does not document the
  compiler, flags or target used. We therefore cannot say how to rebuild this
  exact binary from the pinned commit. Mitigation options: ask the Cap author
  for the build steps and record them in `UPSTREAM.md`; or build our own wasm
  from the pinned commit, publish the recipe, and verify it against the test
  vectors (the module exports `hashwx_alloc`, `hashwx_seed`, `hashwx_make`,
  `hashwx_exec`, `hashwx_free`, `_initialize` and has no imports).
- **Source offer.** `NOTICE` points at the upstream repository and commit but
  does not contain an explicit written offer of the Corresponding Source.
- **Wheel and sdist metadata.** Confirm that PyPI shows the right
  classification (Apache-2.0 for the project, with LGPL-3.0 component noted).

## Questions for the reviewer

1. Is shipping the unmodified prebuilt wasm as a separate, replaceable file
   alongside Apache-2.0 code compatible, with the notices as they stand?
2. Is the pinned-commit pointer enough as the source offer, given the missing
   build recipe, or must we host the source/recipe ourselves?
3. Does the browser copy (served to end users' browsers by Django apps using
   capwx) create additional obligations for the app operators, and should the
   README tell them so?
