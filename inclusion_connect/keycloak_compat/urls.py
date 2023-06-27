from django.urls import re_path
from oauth2_provider import views as oauth2_views

from ..accounts.views import EditUserInfoView
from ..oidc_overrides.views import AuthorizationView, LogoutView, RegistrationView
from . import views


app_name = "keycloak_compat"


urlpatterns = [
    re_path(
        r"^\.well-known/openid-configuration/$",
        oauth2_views.ConnectDiscoveryInfoView.as_view(),
        name="oidc-connect-discovery-info",
    ),
    re_path(r"^protocol/openid-connect/userinfo$", oauth2_views.UserInfoView.as_view(), name="user-info"),
    re_path(r"^protocol/openid-connect/auth$", AuthorizationView.as_view(), name="authorize"),
    re_path(r"^protocol/openid-connect/registrations$", RegistrationView.as_view(), name="registrations"),
    re_path(r"^protocol/openid-connect/token$", oauth2_views.TokenView.as_view(), name="token"),
    re_path(r"^protocol/openid-connect/logout$", LogoutView.as_view(), name="logout"),
    re_path(r"^account$", EditUserInfoView.as_view(), name="edit_user_info"),
    re_path(r"^login-actions/action-token$", views.ActionToken.as_view(), name="action-token"),
]
