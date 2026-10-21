"""URLconf for the capwx contrib tests."""

from django.urls import include, path

from tests.django_project import views

urlpatterns = [
    path("cap/", include("capwx.contrib.django.urls")),
    path("page/", views.page, name="page"),
    path("form/", views.login_form, name="login_form"),
    path("api/protected/", views.protected, name="protected"),
    path("e2e/<str:site>/", views.e2e_page, name="e2e_page"),
]
