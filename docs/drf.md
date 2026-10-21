# Django REST Framework integration

`capwx.contrib.drf` puts capwx into Django REST Framework (DRF). It has three parts:

- the three widget endpoints as `APIView` classes (`ChallengeView`, `RedeemView`, `SiteverifyView`),
- `IsCapVerified` / `cap_permission()`, a permission that requires a verification token on any DRF view,
- `CapTokenField`, a serializer field that checks a token.

Install with the `drf` extra (`pip install "capwx[drf]"`). It needs the same `CAPWX` settings as the
Django contrib, described in the README.

## Widget endpoints

The endpoints delegate to the Django views in `capwx.contrib.django.views`. JSON bodies, status codes,
404 for an unknown site, 413 for bodies over 64 KiB, 400 `invalid_body`, the CSRF gate and the 405 answer
are therefore identical to the Django urls.

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    path("cap/", include("capwx.contrib.drf.urls")),  # namespace "capwx_drf"
]
```

The widget's base endpoint is then `/cap/<site>/`, so set it on the widget:

```html
<cap-widget data-cap-api-endpoint="/cap/login/" data-cap-hidden-field-name="cap-token">
```

Load the scripts as usual with the Django template tags (`{% capwx_scripts %}`).

Behaviour that differs from a stock DRF view, on purpose:

- No DRF authentication, no DRF parsers and no content negotiation. An `Accept` header that DRF
  cannot satisfy does not give 406.
- Any method other than POST gets the Django 405 answer (`{"error": "method_not_allowed"}` with
  `Allow: POST`), not DRF's own 405 body.
- DRF's default response headers are not added, so `Allow` stays `POST`.
- Throttling is DRF's own. The default is no throttling. Set `DEFAULT_THROTTLE_CLASSES` in
  `REST_FRAMEWORK`, or subclass the view and set `throttle_classes`.

## Protecting other DRF views

`IsCapVerified` grants access only with a valid, unused token for a site:

```python
from capwx.contrib.drf import cap_permission


class OrderView(APIView):
    permission_classes = [cap_permission(site="login")]

    def post(self, request): ...
```

- The token comes from the `X-Cap-Token` header first, then from the top-level `cap-token` field of the
  parsed body (`request.data`). Pass `field=""` to accept the header only.
- The token is consumed when it is checked. A second request with the same token fails.
- The decision is cached on the request, so the token is consumed once even when several checks run.
- A failure is a 403 with the body `{"error": "captcha_required"}`, the same body as `require_cap`. It is
  never a 401, even when the view has DRF authentication classes.

To configure it by hand, subclass `IsCapVerified` and set `site`, `header` and `field`.

## Serializers

The widget posts its token as `cap-token`, which is not a valid Python name. `CapTokenField` is therefore
named after its attribute and falls back to the widget key:

```python
from rest_framework import serializers
from capwx.contrib.drf import CapTokenField


class SignupSerializer(serializers.Serializer):
    cap_token = CapTokenField(site="signup")  # reads "cap_token", else "cap-token"
    email = serializers.EmailField()
```

- The token is consumed when the serializer validates it. A blank or missing value does not consume it.
- A wrong, used or expired token gives `{"cap_token": ["Please complete the verification."]}`.
- The field is write-only by default, so the token is not echoed in `serializer.data`.
- To read the token from the `X-Cap-Token` header, put it into the data yourself:
  `SignupSerializer(data={**request.data, "cap_token": request.headers.get("X-Cap-Token")})`.

## Settings

Nothing is needed beyond `CAPWX`. One DRF setting is needed unless you install `django.contrib.auth`:

```python
REST_FRAMEWORK = {"UNAUTHENTICATED_USER": None}
```

DRF's default anonymous user is a `django.contrib.auth` model. If that app is not installed, DRF fails
on every request with `ContentType ... isn't in an application in INSTALLED_APPS`. capwx never reads
`request.user`, so `None` changes nothing it does.

## CSRF

`CAPWX["CSRF_EXEMPT"]` works as in the Django contrib:

- `True` (default): the endpoints are exempt. The token only means something when your CSRF-protected
  form submits it.
- `False`: the endpoints check CSRF on every request. Use `{% capwx_scripts %}` so that
  `CAP_CUSTOM_FETCH` sends the `X-CSRFToken` header.

The DRF views are `csrf_exempt` at Django's middleware level, as the Django views are. The check happens
inside the delegated Django view, so both modes behave the same. Your own DRF views keep DRF's usual CSRF
rules. They use `SessionAuthentication` only if you add it.

## Tests

`tests/test_drf.py` covers the flow, the error paths, both CSRF modes, `IsCapVerified` and `CapTokenField`.
It is skipped when DRF is not installed.
