"""capwx.contrib.django.apps: AppConfig. Validates settings and loads HashWX at startup."""

from django.apps import AppConfig


class CapwxConfig(AppConfig):
    name = "capwx.contrib.django"
    label = "capwx"
    verbose_name = "capwx"

    def ready(self) -> None:
        from capwx import hashwx_ready
        from capwx.contrib.django.conf import validate_settings

        conf = validate_settings()  # raises ImproperlyConfigured on bad CAPWX settings
        wasm_paths = {
            site.config.hashwx_wasm_path
            for site in conf.sites.values()
            if "hashwx" in site.config.protocols
        }
        for wasm_path in sorted(wasm_paths, key=lambda p: p or ""):
            hashwx_ready(wasm_path)
