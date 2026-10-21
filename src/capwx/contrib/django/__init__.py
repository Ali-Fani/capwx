"""capwx.contrib.django: Django integration for capwx.

Add ``"capwx.contrib.django"`` to ``INSTALLED_APPS``, set ``settings.CAPWX`` (see ``conf.py``),
mount ``path("cap/", include("capwx.contrib.django.urls"))``, and load ``{% capwx_scripts %}``
and ``{% capwx_widget site="..." %}`` in templates. Use :class:`CapField` in forms or
:func:`require_cap` on views.
"""
