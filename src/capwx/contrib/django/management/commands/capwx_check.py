"""``manage.py capwx_check``: self-test of the vendored assets and of every configured site.

1. The vendored ``hashwx.wasm`` (inside the package) and the static copy served to browsers both
   match the pinned SHA-256.
2. The four official HashWX test vectors (tevador/hashwx) reproduce.
3. For each configured site, one low-difficulty challenge is minted, solved in-process, and
   redeemed; then the issued token is validated and consumed. Timings are printed.

Solving here is a stand-in for the browser: instrumentation is answered from the expected state,
so it checks the server pipeline, not the browser probe. A site with BLOCK_AUTOMATED_BROWSERS
cannot pass that way, so its check mints without the instrumentation protocol.

Exits non-zero (``CommandError``) on any failure.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import replace
from typing import Any

from django.contrib.staticfiles import finders
from django.core.management.base import BaseCommand, CommandError

from capwx import create_challenge, redeem, validate_token
from capwx._crypto import decrypt_gcm, jwt_verify
from capwx._types import JsonDict, as_json_dict
from capwx.config import CapConfig
from capwx.contrib.django.conf import SiteConf, get_conf
from capwx.protocols import hashwx

_FORMAT_INFO = "cap:fmt2-v1"
_U64 = (1 << 64) - 1
_STATIC_WASM = "capwx/hashwx.wasm"

# Low difficulty so the check is quick. The HashWX target is U64_MAX // d, so d=250 needs ~250
# evaluations per challenge.
_CHECK_OVERRIDES: dict[str, Any] = {
    "hashwx_difficulty": 1000,
    "sha256_difficulty": 1,
}

# tevador/hashwx official vectors: (seed text, nonce, expected hash).
_HASHWX_VECTORS = [
    (b"This is a test seed for hashwx", 0, 0x973684176F8EE362),
    (b"This is a test seed for hashwx", 123456, 0x401983BB07D69B07),
    (b"Lorem ipsum dolor sit amet", 123456, 0x4AF38D834A9A8D3D),
    (b"Lorem ipsum dolor sit amet", 987654321123456789, 0x6A8A5514432E17A3),
]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _solve_sha256(payload: JsonDict) -> JsonDict:
    salt, target = payload["salt"], payload["target"]
    nonce = 0
    while not _sha256_hex((salt + str(nonce)).encode("utf-8")).startswith(target):
        nonce += 1
    return {"nonce": nonce}


def _solve_hashwx(payload: JsonDict, config: CapConfig) -> JsonDict:
    engine = hashwx.get_engine(config.hashwx_wasm_path)
    challenge = bytes.fromhex(payload["c"])
    target = _U64 // payload["d"]
    per_hash = payload["n"]
    nonce = 0
    while True:
        seed = hashlib.sha256(challenge + (nonce // per_hash).to_bytes(8, "little")).digest()
        if engine.hash(seed, nonce) <= target:
            return {"nonce": nonce}
        nonce += 1


def _solve_all(site: SiteConf, response: JsonDict) -> list[JsonDict]:
    payload = jwt_verify(response["token"], site.config.secret)
    if payload is None:
        raise CommandError(f"site {site.name}: freshly minted token does not verify")
    decrypted = as_json_dict(decrypt_gcm(payload["ev"], site.config.secret, _FORMAT_INFO))
    if decrypted is None:
        raise CommandError(f"site {site.name}: encrypted expectations do not decrypt")
    solutions: list[JsonDict] = []
    for public, entry in zip(response["challenges"], decrypted["expected"]):
        proto = public["protocol"]
        if proto == "sha256-pow":
            solutions.append(_solve_sha256(public["payload"]))
        elif proto == "hashwx":
            solutions.append(_solve_hashwx(public["payload"], site.config))
        elif proto == "instrumentation":
            meta = entry["instrMeta"]
            state = dict(zip(meta["vars"], meta["expectedVals"]))
            solutions.append({"instr": {"i": meta["id"], "state": state}})
        else:
            raise CommandError(f"site {site.name}: unknown protocol {proto!r}")
    return solutions


class Command(BaseCommand):
    help = "Verify the HashWX wasm, its test vectors, and a challenge round trip for every site."

    def handle(self, *args: Any, **options: Any) -> None:
        failures: list[str] = []
        self._check_wasm(failures)
        self._check_vectors(failures)
        conf = get_conf()
        for name in conf.sites:
            self._check_site(conf.sites[name], conf.store, failures)
        if failures:
            for line in failures:
                self._write(self.stderr, f"FAIL: {line}")
            raise CommandError(f"capwx_check failed ({len(failures)} problem(s))")
        self._write(self.stdout, "capwx_check: OK")

    def _write(self, stream: Any, text: str) -> None:
        stream.write(text)  # OutputWrapper adds the line ending

    def _check_wasm(self, failures: list[str]) -> None:
        # The check reads the vendored copy directly, so it uses the module's private loaders.
        expected = hashwx._vendored_sha256()  # pyright: ignore[reportPrivateUsage]
        vendored = _sha256_hex(hashwx._read_vendored_wasm())  # pyright: ignore[reportPrivateUsage]
        self._line("vendored hashwx.wasm", vendored == expected, vendored[:16])
        if vendored != expected:
            failures.append("vendored hashwx.wasm sha256 mismatch")
        found = finders.find(_STATIC_WASM)  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
        static_path = found[0] if isinstance(found, list) else found  # pyright: ignore[reportUnknownVariableType]
        if not static_path:
            self._line("static hashwx.wasm", False, "not found by staticfiles")
            failures.append("static hashwx.wasm not found (is capwx.contrib.django installed?)")
            return
        with open(static_path, "rb") as handle:  # pyright: ignore[reportUnknownArgumentType]
            static = _sha256_hex(handle.read())
        self._line("static hashwx.wasm", static == expected, static[:16])
        if static != expected:
            failures.append("static hashwx.wasm sha256 mismatch")

    def _check_vectors(self, failures: list[str]) -> None:
        engine = hashwx.get_engine()
        for seed_text, nonce, expected in _HASHWX_VECTORS:
            seed = seed_text.ljust(32, b"\0")
            got = engine.hash(seed, nonce)
            ok = got == expected
            self._line(f"hashwx vector nonce={nonce}", ok, f"0x{got:016x}")
            if not ok:
                failures.append(f"hashwx vector nonce={nonce}: got 0x{got:016x}")

    def _check_site(self, site: SiteConf, store: Any, failures: list[str]) -> None:
        overrides = dict(_CHECK_OVERRIDES)
        if site.config.instrumentation.block_automated_browsers:
            overrides["protocols"] = tuple(
                p for p in site.config.protocols if p != "instrumentation"
            )
            if not overrides["protocols"]:
                overrides["protocols"] = ("hashwx",)
        config = replace(site.config, **overrides)
        label = f"site {site.name!r}"
        try:
            started = time.perf_counter()
            response = create_challenge(config, scope=site.name, overrides=None)
            mint_ms = (time.perf_counter() - started) * 1000
            started = time.perf_counter()
            solutions = _solve_all(site, response)
            solve_ms = (time.perf_counter() - started) * 1000
            started = time.perf_counter()
            result = redeem(
                config,
                {"token": response["token"], "solutions": solutions},
                scope=site.name,
                nonce_store=store,
                token_store=store,
            )
            redeem_ms = (time.perf_counter() - started) * 1000
        except CommandError as exc:
            failures.append(f"{label}: {exc}")
            self._line(label, False, str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - a diagnostic: any pipeline crash is a failed check
            failures.append(f"{label}: {type(exc).__name__}: {exc}")
            self._line(label, False, f"{type(exc).__name__}: {exc}")
            return
        detail = (
            f"mint {mint_ms:.1f} ms, solve {solve_ms:.1f} ms, redeem {redeem_ms:.1f} ms, "
            f"protocols={','.join(config.protocols)}"
        )
        if not result.success:
            failures.append(f"{label}: redeem failed with {result.reason}")
            self._line(label, False, f"redeem: {result.reason}")
            return
        valid_once = validate_token(config, result.token, scope=site.name, token_store=store)
        replayed = validate_token(config, result.token, scope=site.name, token_store=store)
        ok = valid_once and not replayed
        self._line(label, ok, detail)
        if not ok:
            failures.append(f"{label}: verification token not single-use or not valid")

    def _line(self, label: str, ok: bool, detail: str) -> None:
        mark = "ok  " if ok else "FAIL"
        self._write(self.stdout, f"[{mark}] {label}: {detail}")
