from django.urls import path, re_path

from inclusion_connect.accounts import views


app_name = "accounts"

urlpatterns = [
    re_path(r"^login/$", views.LoginView.as_view(), name="login"),
    re_path(r"^register/$", views.RegisterView.as_view(), name="register"),
    re_path(r"^activate/$", views.ActivateAccountView.as_view(), name="activate"),
    re_path(r"^password_reset/$", views.PasswordResetView.as_view(), name="password_reset"),
    path("reset/<uidb64>/<token>/", views.PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    re_path(r"^accept-terms/$", views.AcceptTermsView.as_view(), name="accept_terms"),
    re_path(r"^my-account/$", views.EditUserInfoView.as_view(), name="edit_user_info"),
    re_path(r"^change-password/$", views.PasswordChangeView.as_view(), name="change_password"),
]
