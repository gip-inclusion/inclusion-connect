from django.contrib import messages
from django.contrib.auth import login, views as auth_views
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.urls import reverse
from django.views.generic import CreateView

from inclusion_connect.accounts import forms
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin


class LoginView(OIDCSessionMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"


class BaseUserCreationView(OIDCSessionMixin, CreateView):
    form_class = forms.RegistrationForm

    def form_valid(self, form):
        # FIXME: change this when adding email verification
        result = super().form_valid(form)
        login(self.request, form.instance)
        return result


class RegistrationView(BaseUserCreationView):
    template_name = "registration.html"

    # TODO: Remove keycloak compatibility
    def dispatch(self, request, *args, **kwargs):
        if all(param in self.get_oidc_params() for param in ["login_hint", "lastname", "firstname"]):
            return HttpResponseRedirect(reverse("accounts:activation"))
        return super().dispatch(request, *args, **kwargs)


class AccountActivationView(BaseUserCreationView):
    form_class = forms.AccountActivationForm
    template_name = "account_activation.html"

    def dispatch(self, request, *args, **kwargs):
        # Check user info is provided
        try:
            self.get_user_info()
        except KeyError:
            return HttpResponseBadRequest()
        return super().dispatch(request, *args, **kwargs)

    def get_user_info(self, raise_exception=False):
        params = self.get_oidc_params()

        # TODO: Remove keycloak compatibility
        try:
            return {
                "email": params["login_hint"],
                "first_name": params["firstname"],
                "last_name": params["lastname"],
            }
        except KeyError:
            return {
                "email": params["email"],
                "first_name": params["firstname"],
                "last_name": params["lastname"],
            }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # TODO Get oauth2 application name from client_id
        return context | {"application_name": "Les emplois de l'inclusion"} | self.get_user_info()

    def get_initial(self):
        return super().get_initial() | self.get_user_info()


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


class PasswordResetConfirmView(OIDCSessionMixin, auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    post_reset_login = True
