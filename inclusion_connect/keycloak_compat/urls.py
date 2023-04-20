from django.urls import re_path
from oauth2_provider import views as oauth2_views

from ..oidc_overrides.views import AuthorizationView, LogoutView


app_name = "keycloak_compat"


urlpatterns = [
    re_path(
        r"^\.well-known/openid-configuration/$",
        oauth2_views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    re_path(r"^\.well-known/jwks.json$", oauth2_views.JwksInfoView.as_view(), name="jwks-info"),
    re_path(r"^userinfo$", oauth2_views.UserInfoView.as_view(), name="user-info"),
    re_path(r"^auth$", AuthorizationView.as_view(), name="authorize"),
    re_path(r"^registrations$", oauth2_views.AuthorizationView.as_view(), name="registrations"),
    re_path(r"^token$", oauth2_views.TokenView.as_view(), name="token"),
    re_path(r"^logout$", LogoutView.as_view(), name="logout"),
]
