from django.contrib import messages
from django.contrib.auth import authenticate, login, views as auth_views
from django.urls import reverse
from django.views.generic import CreateView

from inclusion_connect.accounts import forms


class OidcArgumentMixin:
    def get_success_url(self):
        return self.request.session["next_url"]

    def dispatch(self, request, *args, **kwargs):
        next_url = request.GET.get("next")
        if next_url:
            request.session["next_url"] = next_url
            request.session.modified = True
        return super().dispatch(request, *args, **kwargs)


class LoginView(OidcArgumentMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"


class RegistrationView(OidcArgumentMixin, CreateView):
    form_class = forms.RegistrationForm
    template_name = "registration.html"

    def form_valid(self, form):
        result = super().form_valid(form)
        self.user = authenticate(
            email=form.cleaned_data["email"],
            password=form.cleaned_data["password1"],
        )
        login(self.request, self.user)
        return result


class PasswordResetView(auth_views.PasswordResetView):
    template_name = "password_reset.html"
    form_class = forms.PasswordResetForm

    def get_success_url(self):
        # FIXME: Move where the messages are displayed
        # Or go back to default Django password_reset_done view
        messages.success(
            self.request,
            "Si un compte existe avec cette adresse e-mail, "
            "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
        )
        return reverse("accounts:login")


class PasswordResetConfirmView(OidcArgumentMixin, auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    post_reset_login = True
