"""capwx._crypto: b64url, JWT HS256, AES-GCM and sha256 helpers.

Byte-compatible with upstream ``core/src/crypto.js`` (capjs-core 0.1.5):
tokens minted here validate in Node and vice versa.

Client-supplied input (tokens, blobs) never raises: bad input yields ``None``.
Programmer errors (wrong secret type) still raise.
"""

import base64
import hashlib
import hmac
import json
import os
import re
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from capwx._types import JsonDict, as_json_dict

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]*")
_GCM_IV_LEN = 12
_GCM_TAG_LEN = 16


def random_hex(nbytes: int) -> str:  # JS randomHex(n): n bytes -> 2n hex chars
    return os.urandom(nbytes).hex()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def b64url(data: bytes) -> str:  # Node "base64url": NO padding
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: object) -> bytes:
    """Strict base64url decode (no padding required). Raises ValueError on bad input."""
    if not isinstance(s, str) or _B64URL_RE.fullmatch(s) is None or len(s) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


_JWT_HEADER_B64 = b64url(b'{"alg":"HS256","typ":"JWT"}')  # exact bytes, do not re-serialise


def _key(secret: str | bytes) -> bytes:
    return secret.encode("utf-8") if isinstance(secret, str) else secret


def jwt_sign(payload: JsonDict, secret: str | bytes) -> str:
    body = b64url(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    sig_input = f"{_JWT_HEADER_B64}.{body}"
    sig = hmac.new(_key(secret), sig_input.encode("ascii"), hashlib.sha256).digest()
    return f"{sig_input}.{b64url(sig)}"


def jwt_verify(token: object, secret: str | bytes) -> JsonDict | None:
    """Return the payload dict if the HS256 token is valid, else None. Never raises on bad input."""
    key = _key(secret)  # programmer error (wrong type) is allowed to raise
    if not isinstance(token, str) or not token:
        return None
    first = token.find(".")
    last = token.rfind(".")
    # Exactly two dots, and the first one is not at index 0 (empty header is invalid).
    if first < 1 or first == last or token.find(".", first + 1) != last:
        return None
    try:
        expected = hmac.new(key, token[:last].encode("utf-8"), hashlib.sha256).digest()
        actual = b64url_decode(token[last + 1 :])
    except (ValueError, UnicodeError):
        return None
    if not hmac.compare_digest(expected, actual):
        return None
    try:
        payload: Any = json.loads(b64url_decode(token[first + 1 : last]).decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        return None
    return as_json_dict(payload)


def jwt_sig_hex(token: object) -> str | None:  # hex of the decoded signature (replay key)
    """Hex of the decoded signature segment, or None. Never raises on bad input."""
    if not isinstance(token, str) or not token:
        return None
    last = token.rfind(".")
    if last == -1:
        return None
    try:
        return b64url_decode(token[last + 1 :]).hex()
    except ValueError:
        return None


def _derive_gcm_key(secret: str | bytes, info: str) -> bytes:
    return hmac.new(_key(secret), info.encode("utf-8"), hashlib.sha256).digest()  # 32 bytes


def encrypt_gcm(data: object, secret: str | bytes, info: str = "cap:enc-v1") -> str:
    key = _derive_gcm_key(secret, info)
    iv = os.urandom(_GCM_IV_LEN)
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    # AESGCM.encrypt returns ciphertext || tag; Node's blob layout is iv || tag || ciphertext.
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext, None)
    ct, tag = ct_and_tag[:-_GCM_TAG_LEN], ct_and_tag[-_GCM_TAG_LEN:]
    return b64url(iv + tag + ct)


def decrypt_gcm(blob: object, secret: str | bytes, info: str = "cap:enc-v1") -> Any | None:
    """Decrypt a blob from encrypt_gcm / Node encryptGcm. Returns the JSON value, or None."""
    key = _derive_gcm_key(secret, info)  # programmer error (wrong type) may raise
    try:
        buf = b64url_decode(blob)
        if len(buf) < _GCM_IV_LEN + _GCM_TAG_LEN:
            return None
        iv = buf[:_GCM_IV_LEN]
        tag = buf[_GCM_IV_LEN : _GCM_IV_LEN + _GCM_TAG_LEN]
        ct = buf[_GCM_IV_LEN + _GCM_TAG_LEN :]
        # cryptography expects ciphertext || tag, so reorder the Node layout.
        plaintext = AESGCM(key).decrypt(iv, ct + tag, None)
        value: Any = json.loads(plaintext.decode("utf-8"))
        return value
    except (ValueError, UnicodeError, InvalidTag, RecursionError):
        return None
