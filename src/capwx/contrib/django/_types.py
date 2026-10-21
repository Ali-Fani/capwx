"""capwx.contrib.django._types: typing shim for Django objects.

Django ships no type information (and django-stubs is not a dependency), so request objects are
typed ``Any`` rather than inferred from Django's source. Code that reads them narrows the values it
takes from them (for example with :func:`capwx._types.as_json_dict`).
"""

from __future__ import annotations

from typing import Any, TypeAlias

DjangoRequest: TypeAlias = Any
