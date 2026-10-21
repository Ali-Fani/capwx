"""django-bolt API for the capwx tests (tests/test_bolt.py) and the runbolt smoke test.

Autodiscovery is not used here: tests/django_project/settings_bolt.py names this module in BOLT_API.
"""

from typing import Annotated

from django_bolt import BoltAPI, Depends, Request

from capwx.contrib.bolt import CapRequired, install

api = BoltAPI()
install(api, prefix="/cap")

login_cap = CapRequired(site="login")
header_only_cap = CapRequired(site="login", field="")


@api.post("/protected")
async def protected(
    request: Request, _: Annotated[None, Depends(login_cap.check)]
) -> dict[str, bool]:
    return {"ok": True}


@api.post("/header-only")
async def header_only(
    request: Request, _: Annotated[None, Depends(header_only_cap.check)]
) -> dict[str, bool]:
    return {"ok": True}
