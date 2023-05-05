from django.urls import path, re_path

from inclusion_connect.accounts import views


app_name = "accounts"

urlpatterns = [
    re_path(r"^login/$", views.LoginView.as_view(), name="login"),
    re_path(r"^register/$", views.RegisterView.as_view(), name="register"),
    re_path(r"^activate/$", views.ActivateAccountView.as_view(), name="activate"),
    re_path(r"^password_reset/$", views.PasswordResetView.as_view(), name="password_reset"),
    path("reset/<uidb64>/<token>/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
]
