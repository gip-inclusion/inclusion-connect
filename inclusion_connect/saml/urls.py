from django.urls import re_path

from inclusion_connect.saml import views


app_name = "saml"

urlpatterns = [
    re_path(r"^metadata/?$", views.MetadataView.as_view(), name="metadata"),
    re_path(r"^sso/?$", views.SsoView.as_view(), name="sso"),
    re_path(r"^sso/continue/?$", views.ContinueSsoView.as_view(), name="sso_continue"),
    re_path(r"^slo/?$", views.SloView.as_view(), name="slo"),
]
