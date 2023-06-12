from django.urls import re_path
from oauth2_provider import views as oauth2_views

from inclusion_connect.oidc_overrides import views


app_name = "oauth2_provider"

urlpatterns = [
    re_path(r"^authorize/", views.AuthorizationView.as_view(), name="authorize"),
    re_path(r"^register/", views.RegistrationView.as_view(), name="register"),
    re_path(r"^activate/", views.ActivationView.as_view(), name="activate"),
    re_path(r"^token/$", oauth2_views.TokenView.as_view(), name="token"),
    re_path(r"^revoke_token/$", oauth2_views.RevokeTokenView.as_view(), name="revoke-token"),
    re_path(r"^introspect/$", oauth2_views.IntrospectTokenView.as_view(), name="introspect"),
    # OIDC urls
    re_path(
        r"^\.well-known/openid-configuration/$",
        oauth2_views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    re_path(r"^\.well-known/jwks.json$", oauth2_views.JwksInfoView.as_view(), name="jwks-info"),
    re_path(r"^userinfo/$", oauth2_views.UserInfoView.as_view(), name="user-info"),
    re_path(r"^logout/", views.LogoutView.as_view(), name="logout"),
]
