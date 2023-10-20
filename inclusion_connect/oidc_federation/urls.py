from django.conf import settings
from django.urls import include, re_path

from . import peama


app_name = "oidc_federation"

urlpatterns = []

if settings.PEAMA_ENABLED:
    peama_urlpatterns = [
        re_path(r"^callback/", peama.OIDCAuthenticationCallbackView.as_view(), name="callback"),
        re_path(r"^authenticate/", peama.OIDCAuthenticationRequestView.as_view(), name="init"),
        # Logout is handle with a function
    ]
    urlpatterns.append(re_path(r"^peama/", include((peama_urlpatterns, "peama"))))
