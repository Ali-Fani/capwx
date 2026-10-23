"""Minimal Django settings for the capwx contrib tests (no database, locmem cache)."""

from __future__ import annotations

from pathlib import Path

from capwx import hashwx_available

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = "django-insecure-capwx-tests-only-not-for-production"
DEBUG = False
ALLOWED_HOSTS = ["testserver", "localhost", "127.0.0.1"]

INSTALLED_APPS = [
    "django.contrib.staticfiles",
    "capwx.contrib.django",
]

MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
]

ROOT_URLCONF = "tests.django_project.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.csrf",
            ],
        },
    },
]

DATABASES: dict[str, dict[str, str]] = {}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "capwx-tests",
    }
}

STATIC_URL = "/static/"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Without a wasmtime wheel (see docs/platforms.md) a HashWX site would fail at startup, so the test
# project then defaults to sha256-pow. The suite still runs there; the HashWX tests are the ones
# that need wasmtime.
_DEFAULT_PROTOCOLS = (
    ["hashwx", "instrumentation"]
    if hashwx_available()
    else [
        "sha256-pow",
        "instrumentation",
    ]
)

CAPWX = {
    "SECRET": "capwx-test-secret-0123456789abcdef",
    "STORE": "capwx.stores.django_cache.DjangoCacheStore",
    "STORE_OPTIONS": {"alias": "default"},
    "PROTOCOLS": _DEFAULT_PROTOCOLS,
    "HASHWX_DIFFICULTY": 1000,  # 4 challenges of d=250: a few hundred hashes each
    "CSRF_EXEMPT": True,
    "DIFFICULTY_HOOK": "tests.django_project.hooks.difficulty",
    "BEFORE_CHALLENGE_HOOK": "tests.django_project.hooks.before_challenge",
    "SITES": {
        "default": {"SITE_SECRET": "default-site-secret-0123"},
        "login": {"SITE_SECRET": "login-site-secret-0123456"},
        "signup": {"PROTOCOLS": ["sha256-pow"], "SITE_SECRET": "signup-site-secret-01234"},
        "strict": {"INSTRUMENTATION": {"BLOCK_AUTOMATED_BROWSERS": True}},
        # Browser e2e sites (tests/e2e). Real widget + real Chromium; see §13.3.
        "e2e": {"HASHWX_DIFFICULTY": 20_000, "INSTRUMENTATION": {"OBFUSCATION_LEVEL": 3}},
        "e2e-obf1": {"HASHWX_DIFFICULTY": 20_000, "INSTRUMENTATION": {"OBFUSCATION_LEVEL": 1}},
        "e2e-obf4": {"HASHWX_DIFFICULTY": 20_000, "INSTRUMENTATION": {"OBFUSCATION_LEVEL": 4}},
        "e2e-obf7": {"HASHWX_DIFFICULTY": 20_000, "INSTRUMENTATION": {"OBFUSCATION_LEVEL": 7}},
        "e2e-blocking": {
            "HASHWX_DIFFICULTY": 20_000,
            "INSTRUMENTATION": {"BLOCK_AUTOMATED_BROWSERS": True},
        },
        # Served under a strict CSP without 'unsafe-eval' by the CSP tests; the second site opts in.
        "e2e-csp": {"HASHWX_DIFFICULTY": 20_000},
        "e2e-csp-allow": {
            "HASHWX_DIFFICULTY": 20_000,
            "INSTRUMENTATION": {"ALLOW_CSP_EVAL_BLOCKED": True},
        },
        # No hashwx: sha256-pow challenges only (few, easy) plus instrumentation.
        "e2e-nohashwx": {
            "PROTOCOLS": ["sha256-pow", "instrumentation"],
            "SHA256_COUNT": 4,
            "SHA256_DIFFICULTY": 4,
        },
    },
}
