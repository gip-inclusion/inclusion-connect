from django.contrib.auth import logout, views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import TemplateView

from inclusion_connect.accounts import forms
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
