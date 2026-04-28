from django.urls import path, re_path

from inclusion_connect.accounts import views


app_name = "accounts"

urlpatterns = [
    re_path(r"^login/$", views.LoginView.as_view(), name="login"),
    re_path(r"^password_reset/$", views.PasswordResetView.as_view(), name="password_reset"),
    path("reset/<uidb64>/<token>/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    re_path(
        r"^change-temporary-password/$", views.ChangeTemporaryPassword.as_view(), name="change_temporary_password"
    ),
    re_path(r"^home/$", views.HomeView.as_view(), name="home"),
    re_path(r"^change-password/$", views.PasswordChangeView.as_view(), name="change_password"),
    re_path(r"^change-weak-password/$", views.ChangeWeakPassword.as_view(), name="change_weak_password"),
]
