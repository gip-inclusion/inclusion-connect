from django.urls import re_path

from inclusion_connect.oidc_overrides import views


app_name = "oidc_overrides"

urlpatterns = [
    re_path(r"^authorize/", views.AuthorizationView.as_view(), name="authorize"),
    re_path(r"^registrations/", views.RegistrationView.as_view(), name="registrations"),
    re_path(r"^activation/", views.ActivationView.as_view(), name="activation"),
    re_path(r"^logout/", views.LogoutView.as_view(), name="logout"),
]
