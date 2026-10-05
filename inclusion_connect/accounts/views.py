from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout, views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import FormView, TemplateView

from inclusion_connect.accounts import forms
from inclusion_connect.accounts.helpers import get_next_url, login
from inclusion_connect.logging import log
from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin


LOGGER_NAME = "inclusion_connect.auth"


class LoginView(OIDCSessionMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"
    EVENT_NAME = "login"

    def form_invalid(self, form):
        log(
            LOGGER_NAME,
            self.request,
            email=form.cleaned_data.get("email"),
            event=f"{self.EVENT_NAME}_error",
            errors=form.errors.get_json_data(),
        )
        return super().form_invalid(form)

    def form_valid(self, form):
        log(
            LOGGER_NAME,
            self.request,
            user=form.user_cache.email,
            event=self.EVENT_NAME,
        )
        return super().form_valid(form)


@require_POST
def logout_view(request):
    user = request.user
    logout(request)
    log(
        LOGGER_NAME,
        request,
        user=user,
        event="logout",
    )
    return redirect("accounts:login")


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    post_reset_login = True
    EVENT_NAME = "reset_password"
    post_reset_login_backend = settings.DEFAULT_AUTH_BACKEND
    success_url = None

    def get_success_url(self):
        return get_next_url(self.request)

    def log(self, event_name, **kwargs):
        log(
            LOGGER_NAME,
            self.request,
            event=event_name,
            user=self.user.email,
            **kwargs,
        )

    def form_invalid(self, form):
        self.log(
            f"{self.EVENT_NAME}_error",
            errors=form.errors.get_json_data(),
        )
        return super().form_invalid(form)

    def form_valid(self, form):
        self.log(self.EVENT_NAME)
        self.log(LoginView.EVENT_NAME)  # Also log a login here
        return super().form_valid(form)


class ChangeTemporaryPassword(LoginRequiredMixin, FormView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    EVENT_NAME = "change_temporary_password"

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.request.user}

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"validlink": True}

    def get_success_url(self):
        return get_next_url(self.request)

    def log(self, event_name, **kwargs):
        log(
            LOGGER_NAME,
            self.request,
            event=event_name,
            user=self.request.user.email,
            **kwargs,
        )

    def form_invalid(self, form):
        self.log(
            f"{self.EVENT_NAME}_error",
            errors=form.errors.get_json_data(),
        )
        return super().form_invalid(form)

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        self.log(self.EVENT_NAME)
        return super().form_valid(form)


class MyAccountMixin(LoginRequiredMixin):
    application = None

    def setup(self, request, *args, **kwargs):
        referrer = request.GET.get("referrer")
        self.application = Application.objects.filter(client_id=referrer).first()
        return super().setup(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context | {
            "home": {
                "url": reverse("accounts:home"),
                "active": False,
            },
            "edit_password": {
                "url": reverse("accounts:change_password"),
                "active": False,
            },
        }

    def get_object(self, queryset=None):
        return self.request.user

    def get_success_url(self):
        # Stay on page
        return self.request.get_full_path()


class HomeView(MyAccountMixin, TemplateView):
    template_name = "account_home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["home"]["active"] = True
        return context


class PasswordChangeView(MyAccountMixin, FormView):
    template_name = "change_password.html"
    form_class = forms.PasswordChangeForm
    EVENT_NAME = "change_password"

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.get_object()}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["edit_password"]["active"] = True
        return context

    def log(self, event_name, **kwargs):
        if self.application:
            kwargs["application"] = self.application.client_id
        log(
            LOGGER_NAME,
            self.request,
            event=event_name,
            user=self.request.user.email,
            **kwargs,
        )

    def form_invalid(self, form):
        self.log(f"{self.EVENT_NAME}_error", errors=form.errors.get_json_data())
        return super().form_invalid(form)

    def form_valid(self, form):
        form.save()
        login(self.request, self.get_object())
        self.log(self.EVENT_NAME)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        return super().form_valid(form)


class ChangeWeakPassword(ChangeTemporaryPassword):
    EVENT_NAME = "change_weak_password"

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"weak_password": True}

    def form_valid(self, form):
        form.user.password_is_too_weak = False
        return super().form_valid(form)
