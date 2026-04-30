import logging
from functools import partial

from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.urls import reverse
from django.views.generic import FormView, TemplateView

from inclusion_connect.accounts import forms
from inclusion_connect.accounts.helpers import login
from inclusion_connect.logging import log_data
from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.utils.oidc import get_next_url


logger = logging.getLogger("inclusion_connect.auth")


EMAIL_CONFIRM_KEY = "email_to_confirm"


class LoginView(OIDCSessionMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"
    EVENT_NAME = "login"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["log"] = log_data(self.request)
        return kwargs

    def form_invalid(self, form):
        log = form.log
        log["event"] = f"{self.EVENT_NAME}_error"
        log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))
        return super().form_invalid(form)

    def form_valid(self, form):
        response = super().form_valid(form)
        log = form.log
        log["event"] = self.EVENT_NAME
        transaction.on_commit(partial(logger.info, log))
        return response


class ChangeTemporaryPassword(LoginRequiredMixin, FormView):
    template_name = "password_confirm.html"
    form_class = forms.SetPasswordForm
    EVENT_NAME = "change_temporary_password"

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.request.user}

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"validlink": True}

    def get_success_url(self):
        return get_next_url(self.request)

    def log(self, event_name, form):
        log = log_data(self.request)
        log["event"] = event_name
        log["user"] = self.request.user.pk
        if form.errors:
            log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        self.log(f"{self.EVENT_NAME}_error", form)
        return response

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        self.log(self.EVENT_NAME, form)
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

    def log(self, event_name, form):
        log = log_data(self.request)
        log["event"] = event_name
        log["user"] = self.request.user.pk
        if self.application:
            log["application"] = self.application.client_id
        if form.errors:
            log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        self.log(f"{self.EVENT_NAME}_error", form)
        return response

    def form_valid(self, form):
        form.save()
        login(self.request, self.get_object())
        self.log(self.EVENT_NAME, form)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        return super().form_valid(form)


class ChangeWeakPassword(ChangeTemporaryPassword):
    EVENT_NAME = "change_weak_password"

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"weak_password": True}

    def form_valid(self, form):
        form.user.password_is_too_weak = False
        return super().form_valid(form)
