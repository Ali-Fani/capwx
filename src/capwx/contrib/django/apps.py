"""capwx.contrib.django.apps: AppConfig. Validates settings and loads HashWX at startup."""

from django.apps import AppConfig
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from capwx._assets_path import ASSETS_DIR


class CapwxConfig(AppConfig):
    name = "capwx.contrib.django"
    label = "capwx"
    verbose_name = "capwx"

    def ready(self) -> None:
        from capwx import hashwx_available, hashwx_ready
        from capwx.contrib.django.conf import validate_settings
        from capwx.protocols.hashwx import missing_wasmtime_message

        # Serve the vendored browser assets under the URL prefix /static/capwx/.
        assets_entry = ("capwx", str(ASSETS_DIR))
        dirs = list(settings.STATICFILES_DIRS)
        if assets_entry not in dirs:
            dirs.append(assets_entry)
            settings.STATICFILES_DIRS = dirs
            # The finders cache their locations; clear it so an earlier lookup cannot hide the assets.
            from django.contrib.staticfiles import finders

            finders.get_finder.cache_clear()

        conf = validate_settings()  # raises ImproperlyConfigured on bad CAPWX settings
        hashwx_sites = sorted(
            name for name, site in conf.sites.items() if "hashwx" in site.config.protocols
        )
        # Sites that never list hashwx (sha256-pow only) need no wasmtime, so they start normally.
        if hashwx_sites and not hashwx_available():
            raise ImproperlyConfigured(
                f"{missing_wasmtime_message()} Sites using hashwx: {', '.join(hashwx_sites)}."
            )
        wasm_paths = {conf.sites[name].config.hashwx_wasm_path for name in hashwx_sites}
        for wasm_path in sorted(wasm_paths, key=lambda p: p or ""):
            hashwx_ready(wasm_path)
