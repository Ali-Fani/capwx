"""capwx.contrib.ninja: Django Ninja integration for capwx (plan §11, M11).

``build_router()`` gives the three widget endpoints (challenge, redeem, siteverify) as a ninja
router. ``CapRequired`` is an auth class that protects any ninja operation with a verification
token. ``install(api)`` makes its failures answer with the ``require_cap`` body. See
:mod:`capwx.contrib.ninja.router` for mounting and CSRF notes.
"""

from capwx.contrib.ninja.router import CapRequired, CaptchaRequired, build_router, install

__all__ = ["CapRequired", "CaptchaRequired", "build_router", "install"]
