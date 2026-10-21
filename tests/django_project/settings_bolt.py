"""The test settings plus django-bolt, for ``python -m django runbolt`` (see docs/bolt.md).

``tests/django_project/settings.py`` stays as it is: the pytest suite does not need the
``django_bolt`` app. Everything here is the same settings module with two additions.
"""

import tests.django_project.settings as _base

globals().update({name: value for name, value in vars(_base).items() if name.isupper()})

INSTALLED_APPS = [*_base.INSTALLED_APPS, "django_bolt"]
BOLT_API = ["tests.django_project.bolt_api:api"]
