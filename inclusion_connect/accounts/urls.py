from django.urls import path, re_path

from inclusion_connect.accounts import views


app_name = "accounts"

urlpatterns = [
    re_path(r"^login/$", views.LoginView.as_view(), name="login"),
    re_path(r"^registration/$", views.RegistrationView.as_view(), name="registration"),
    re_path(r"^activation/$", views.AccountActivationView.as_view(), name="activation"),
    re_path(r"^password_reset/$", views.PasswordResetView.as_view(), name="password_reset"),
    path("reset/<uidb64>/<token>/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
