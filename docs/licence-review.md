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
   pointer to it (§4/§6). **Source offer: done** (`NOTICE`, written offer to
   alifani1377@gmail.com). **Vendored source: done** (unmodified HashWX tree at
   the pinned commit in `third_party/hashwx/`, in the sdist, not in the wheel,
   checked by `scripts/check_dist.py`). **Build recipe: still open**, see below.
4. Provide a way to relink/replace the library with a modified version (§4(d)):
   `hashwx_wasm_path` and the static-file override. Note that the server-side
   path is *not* hash-checked, deliberately, so a replacement is accepted.
   **Reviewer: confirm this meets "suitable shared library mechanism".**

## Provenance findings (what the binary and upstream show)

Checked by parsing `hashwx.wasm` directly and reading the Cap and HashWX
repositories at the pinned commits. Full detail is in
`third_party/hashwx/README.capwx.md`.

- **No shim source exists in Cap.** `hashwx_seed` and the other extra exports
  (`hashwx_registers`, `hashwx_memory`, `hashwx_module`, `hashwx_module_size`,
  `hashwx_exec_begin`, `hashwx_exec_final`) are defined in tevador's own
  `src/hashwx.c` at the pinned commit, not in Cap. The binary's export set
  matches the `EXPORTED_FUNCTIONS` list in tevador's `CMakeLists.txt` Emscripten
  target, plus Emscripten runtime helpers. The likely build is that target,
  which is an inference and is not verified.
- **Cap does not build it.** Cap's `wasm/build.js` builds only the Rust
  `cap_wasm` package. `wasm/src/browser/hashwx.wasm` is a copy of the same
  binary, not a build output. The Cap commit history has no build notes.
- **The binary is stripped.** It has no `producers`, `name` or
  `target_features` custom section, so the compiler and Emscripten versions
  cannot be recovered from it. The only build note is a comment in Cap's
  generated `hashwx-wasm.js`: "Built with emcc, lowered to WebAssembly 1.0
  (MVP)". It gives no version or flags.
- **Nothing has been compiled or executed.** The rebuild and the MVP claim are
  unverified.

## Known gaps

- **Exact build recipe unknown (open).** The emsdk version, optimisation level,
  exact CMake invocation and whether the `wasm-opt` lowering was run are not
  recorded anywhere we can see. A rebuild from the pinned commit is possible
  (`emcmake cmake` and the CMake Emscripten target), but it will not be
  byte-identical, and that has not been tried. Options: ask the Cap author for
  the build steps and record them in `UPSTREAM.md` (a suggestion only, nobody has
  been contacted); or build our own wasm from the pinned commit with a pinned
  emsdk, publish that recipe, and verify it by behaviour (the `node` interop
  suite and the Cap vectors).
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
