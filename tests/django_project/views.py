"""Test views: a page with the widget, a form with CapField, and a require_cap-protected API."""

from django.http import Http404, JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_POST

from capwx.contrib.django.decorators import require_cap
from tests.django_project.forms import LoginForm, e2e_form_class

# Sites with a browser e2e page (settings CAPWX.SITES; see tests/e2e and plan §13.3).
E2E_SITES = ("e2e", "e2e-obf1", "e2e-obf4", "e2e-obf7", "e2e-blocking", "e2e-nohashwx")


def page(request):
    return render(request, "test/page.html")


def e2e_page(request, site: str):
    """GET: the real widget in a form. POST: CapField validation; JSON says whether it was valid."""
    if site not in E2E_SITES:
        raise Http404("unknown e2e site")
    form_class = e2e_form_class(site)
    if request.method == "POST":
        form = form_class(request.POST)
        if form.is_valid():
            return JsonResponse({"ok": True, "site": site})
        return JsonResponse({"ok": False, "errors": form.errors.get_json_data()}, status=400)
    return render(request, "test/e2e.html", {"site": site, "form": form_class()})


def login_form(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            return JsonResponse({"ok": True})
        return JsonResponse({"ok": False, "errors": form.errors.get_json_data()}, status=400)
    return render(request, "test/form.html", {"form": LoginForm()})


@require_POST
@require_cap(site="login")
def protected(request):
    return JsonResponse({"ok": True})
