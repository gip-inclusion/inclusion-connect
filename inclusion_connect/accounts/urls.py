from django.urls import re_path

from inclusion_connect.accounts import views


app_name = "accounts"

urlpatterns = [
    re_path(r"^login/$", views.LoginView.as_view(), name="login"),
    re_path(r"^registration/$", views.RegistrationView.as_view(), name="registration"),
]
