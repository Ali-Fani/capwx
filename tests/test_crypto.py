"""Crypto primitives vs. the committed vectors (byte-compat with upstream crypto.js)."""

import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from capwx._crypto import (
    b64url,
    b64url_decode,
    decrypt_gcm,
    encrypt_gcm,
    jwt_sig_hex,
    jwt_sign,
    jwt_verify,
    random_hex,
    sha256_hex,
)

VECTORS_DIR = Path(__file__).parent / "vectors"
VEC = json.loads((VECTORS_DIR / "vectors.json").read_text(encoding="utf-8"))
GEN = json.loads((VECTORS_DIR / "crypto.json").read_text(encoding="utf-8"))
SECRET = VEC["secret"]
JWT = VEC["jwt"]
GCM_INFO = "cap:fmt2-v1"
GCM_PAYLOAD = {"expected": [{"protocol": "sha256-pow", "salt": "ab", "target": "0000"}]}
JWT_PAYLOAD = {"f": 2, "n": "00ff", "exp": 1893456000000, "iat": 1893455400000, "sk": "login"}


def _raw_jwt(body: bytes, secret: str = SECRET) -> str:
    """Build a correctly signed HS256 token around arbitrary body bytes."""
    header = b64url(b'{"alg":"HS256","typ":"JWT"}')
    sig_input = f"{header}.{b64url(body)}"
    sig = hmac.new(secret.encode(), sig_input.encode("ascii"), hashlib.sha256).digest()
    return f"{sig_input}.{b64url(sig)}"


def _flip_byte(blob: str, index: int) -> str:
    raw = bytearray(b64url_decode(blob))
    raw[index] ^= 0x01
    return b64url(bytes(raw))


# --- helpers ---------------------------------------------------------------


def test_random_hex_length():
    assert len(random_hex(16)) == 32
    assert random_hex(8) != random_hex(8)


def test_sha256_hex_known_value():
    assert sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_b64url_no_padding_and_roundtrip():
    data = bytes(range(256))
    enc = b64url(data)
    assert "=" not in enc and "+" not in enc and "/" not in enc
    assert b64url_decode(enc) == data
    assert b64url_decode("") == b""


@pytest.mark.parametrize("bad", ["a", "ab!c", "a b", "é", None, 123, b"abcd"])
def test_b64url_decode_rejects_bad_input(bad):
    with pytest.raises(ValueError):
        b64url_decode(bad)


# --- JWT -------------------------------------------------------------------


@pytest.mark.parametrize("vectors", [VEC, GEN], ids=["vectors.json", "crypto.json"])
def test_jwt_verify_vector(vectors):
    assert jwt_verify(vectors["jwt"], vectors["secret"]) == JWT_PAYLOAD


def test_jwt_sign_reproduces_vector_bytes():
    # Same key order + compact separators as JS JSON.stringify -> identical token.
    assert jwt_sign(JWT_PAYLOAD, SECRET) == JWT


def test_jwt_sign_accepts_bytes_secret():
    assert jwt_sign(JWT_PAYLOAD, SECRET.encode()) == JWT


def test_jwt_wrong_secret_is_none():
    assert jwt_verify(JWT, "another-secret-0123456789") is None


def test_jwt_tampered_payload_is_none():
    head, _body, sig = JWT.split(".")
    tampered_body = b64url(json.dumps({**JWT_PAYLOAD, "sk": "admin"}).encode())
    assert jwt_verify(f"{head}.{tampered_body}.{sig}", SECRET) is None


def test_jwt_bad_signature_is_none():
    head, body, sig = JWT.split(".")
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert jwt_verify(f"{head}.{body}.{flipped}", SECRET) is None
    assert jwt_verify(f"{head}.{body}.", SECRET) is None


def test_jwt_three_dots_is_none():
    assert jwt_verify(JWT + ".x", SECRET) is None
    head, body, sig = JWT.split(".")
    assert jwt_verify(f"{head}.{body}.{sig}.", SECRET) is None


def test_jwt_one_dot_is_none():
    head, body, _sig = JWT.split(".")
    assert jwt_verify(f"{head}.{body}", SECRET) is None


def test_jwt_first_dot_at_index_zero_is_none():
    assert jwt_verify("." + JWT, SECRET) is None
    assert jwt_verify("..", SECRET) is None


def test_jwt_non_json_payload_is_none():
    assert jwt_verify(_raw_jwt(b"not json at all"), SECRET) is None


@pytest.mark.parametrize("body", [b"[1,2]", b"42", b'"str"', b"null", b"true"])
def test_jwt_non_object_payload_is_none(body):
    assert jwt_verify(_raw_jwt(body), SECRET) is None


def test_jwt_non_utf8_payload_is_none():
    assert jwt_verify(_raw_jwt(b"\xff\xfe{}"), SECRET) is None


def test_jwt_deeply_nested_payload_is_none():
    assert jwt_verify(_raw_jwt(b"[" * 100_000 + b"]" * 100_000), SECRET) is None


def test_jwt_valid_object_payload_from_raw_builder():
    assert jwt_verify(_raw_jwt(b'{"f":2}'), SECRET) == {"f": 2}


@pytest.mark.parametrize(
    "bad",
    ["", None, 123, b"bytes", "garbage", "a.b", "é.é.é", "a..b", "!!.!!.!!", "a.b.c.d"],
)
def test_jwt_garbage_is_none(bad):
    assert jwt_verify(bad, SECRET) is None


def test_jwt_sig_hex_matches_decoded_signature():
    sig = base64.urlsafe_b64decode(JWT.rsplit(".", 1)[1] + "==")
    assert len(sig) == 32
    assert jwt_sig_hex(JWT) == sig.hex()


def test_jwt_sig_hex_differs_per_signature():
    other = jwt_sign({**JWT_PAYLOAD, "n": "0100"}, SECRET)
    assert jwt_sig_hex(other) != jwt_sig_hex(JWT)


@pytest.mark.parametrize("bad", ["", None, 5, "nodots", "a.b!c", "x.y z"])
def test_jwt_sig_hex_bad_input_is_none(bad):
    assert jwt_sig_hex(bad) is None


# --- AES-GCM ---------------------------------------------------------------


@pytest.mark.parametrize("vectors", [VEC, GEN], ids=["vectors.json", "crypto.json"])
def test_decrypt_gcm_vector(vectors):
    assert decrypt_gcm(vectors["gcm"], vectors["secret"], GCM_INFO) == GCM_PAYLOAD


def test_decrypt_gcm_generated_file_payload():
    assert GEN["gcm_info"] == GCM_INFO
    assert decrypt_gcm(GEN["gcm"], GEN["secret"], GEN["gcm_info"]) == GEN["gcm_payload"]


def test_gcm_roundtrip():
    blob = encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)
    assert decrypt_gcm(blob, SECRET, GCM_INFO) == GCM_PAYLOAD


def test_gcm_roundtrip_default_info_and_unicode():
    data = {"msg": "héllo \U0001f600", "n": [1, 2, 3]}
    blob = encrypt_gcm(data, SECRET)
    assert decrypt_gcm(blob, SECRET) == data


def test_gcm_random_iv_each_time():
    assert encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO) != encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)


def test_gcm_layout_is_iv_tag_ct():
    # Node layout: iv(12) | tag(16) | ciphertext. Re-derive the key and decrypt with plain AESGCM.
    blob = encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)
    raw = b64url_decode(blob)
    iv, tag, ct = raw[:12], raw[12:28], raw[28:]
    key = hmac.new(SECRET.encode(), GCM_INFO.encode(), hashlib.sha256).digest()
    plaintext = AESGCM(key).decrypt(iv, ct + tag, None)
    assert json.loads(plaintext) == GCM_PAYLOAD


def test_gcm_tampered_ciphertext_is_none():
    blob = encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)
    assert decrypt_gcm(_flip_byte(blob, -1), SECRET, GCM_INFO) is None


def test_gcm_tampered_tag_is_none():
    blob = encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)
    assert decrypt_gcm(_flip_byte(blob, 12), SECRET, GCM_INFO) is None


def test_gcm_tampered_iv_is_none():
    blob = encrypt_gcm(GCM_PAYLOAD, SECRET, GCM_INFO)
    assert decrypt_gcm(_flip_byte(blob, 0), SECRET, GCM_INFO) is None


def test_gcm_wrong_info_is_none():
    assert decrypt_gcm(VEC["gcm"], SECRET, "cap:enc-v1") is None
    assert decrypt_gcm(VEC["gcm"], SECRET) is None


def test_gcm_wrong_secret_is_none():
    assert decrypt_gcm(VEC["gcm"], "another-secret-0123456789", GCM_INFO) is None


def test_gcm_non_object_plaintext_returned_as_json_value():
    # decrypt_gcm returns the JSON value; shape checks belong to the caller.
    blob = encrypt_gcm([1, 2], SECRET, GCM_INFO)
    assert decrypt_gcm(blob, SECRET, GCM_INFO) == [1, 2]


@pytest.mark.parametrize("bad", ["", "A", "AAAA", None, 42, "!!!!", "x" * 40 + "!"])
def test_gcm_garbage_is_none(bad):
    assert decrypt_gcm(bad, SECRET, GCM_INFO) is None


def test_gcm_short_blob_is_none():
    # 27 bytes: one short of iv(12) + tag(16), rejected before decrypting.
    assert decrypt_gcm(b64url(bytes(27)), SECRET, GCM_INFO) is None


def test_gcm_header_length_only_is_none():
    # 28 bytes: iv + tag and empty ciphertext; authentication fails -> None.
    assert decrypt_gcm(b64url(bytes(28)), SECRET, GCM_INFO) is None
