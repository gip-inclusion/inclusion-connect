from django.urls import re_path

from inclusion_connect.saml import views


app_name = "saml"

urlpatterns = [
    re_path(r"^metadata/?$", views.MetadataView.as_view(), name="metadata"),
    re_path(r"^sso/?$", views.SsoView.as_view(), name="sso"),
]
