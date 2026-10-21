"""capwx.contrib.bolt: django-bolt integration (plan section 11.2, Bolt flavour).

Needs ``django-bolt`` (``pip install 'capwx[bolt]'``), which needs Python 3.12 or newer. Importing
this package without it raises ImportError with that hint. The Django integration
(``capwx.contrib.django``) does not need this package.

Mount the widget endpoints on a ``BoltAPI`` and guard handlers with :class:`CapRequired`. See
``docs/bolt.md``.
"""

from __future__ import annotations

import importlib
import sys

if sys.version_info[:2] < (3, 12):
    raise ImportError(
        "capwx.contrib.bolt needs Python 3.12 or newer, because django-bolt requires it. "
        f"This interpreter is {sys.version.split()[0]}; use capwx.contrib.django or "
        "capwx.contrib.ninja instead."
    )

try:
    importlib.import_module("django_bolt")
except ImportError as exc:
    raise ImportError(
        "capwx.contrib.bolt needs django-bolt, which is not installed. "
        "Install it with: pip install 'capwx[bolt]' (or: pip install django-bolt>=0.12)"
    ) from exc

from capwx.contrib.bolt.router import CapRequired, build_router, install

__all__ = ["CapRequired", "build_router", "install"]
