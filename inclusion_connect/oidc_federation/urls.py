from django.urls import include, re_path

from . import peama


app_name = "oidc_federation"

peama_urlpatterns = [
    re_path(r"^callback/", peama.OIDCAuthenticationCallbackView.as_view(), name="callback"),
    re_path(r"^authenticate/", peama.OIDCAuthenticationRequestView.as_view(), name="init"),
    re_path(r"^logout/", peama.OIDCLogoutView.as_view(), name="logout"),
]

urlpatterns = [
    re_path(r"^peama/", include((peama_urlpatterns, "peama"))),
]
