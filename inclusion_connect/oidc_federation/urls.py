from django.urls import include, re_path

from . import peama


app_name = "oidc_federation"

peama_urlpatterns = [
    re_path(r"^callback/", peama.OIDCAuthenticationCallbackView.as_view(), name="callback"),
    re_path(r"^authenticate/", peama.OIDCAuthenticationRequestView.as_view(), name="init"),
    # There's no logout available on PEAMA
]

urlpatterns = [
    re_path(r"^peama/", include((peama_urlpatterns, "peama"))),
]
