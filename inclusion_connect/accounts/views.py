from base64 import b32encode

import segno
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import FormView, TemplateView
from django_otp import devices_for_user, login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice

from inclusion_connect.accounts import forms
from inclusion_connect.accounts.helpers import create_new_totp_device, get_next_url, login
from inclusion_connect.logging import log
from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.models import User
from inclusion_connect.utils.oidc import initial_from_login_hint


LOGGER_NAME = "inclusion_connect.auth"


EMAIL_CONFIRM_KEY = "email_to_confirm"


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


class PasswordResetView(auth_views.PasswordResetView):
    template_name = "password_reset.html"
    subject_template_name = "registration/password_reset_subject.txt"
    email_template_name = "registration/password_reset_body.txt"
    html_email_template_name = "registration/password_reset_body.html"
    form_class = forms.PasswordResetForm
    EVENT_NAME = "forgot_password"

    def get_initial(self):
        initial = super().get_initial()
        initial.update(initial_from_login_hint(self.request))
        return initial

    def get_success_url(self):
        messages.success(
            self.request,
            "Si un compte existe avec cette adresse e-mail, "
            "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
        )
        return reverse("accounts:login")

    def form_invalid(self, form):
        log(
            LOGGER_NAME,
            self.request,
            event=f"{self.EVENT_NAME}_error",
            email=form.cleaned_data.get("email", form.data.get("email", "")),
        )
        return super().form_invalid(form)

    def form_valid(self, form):
        email = form.cleaned_data.get("email")
        if User.objects.filter(email=email).exists():
            log(
                LOGGER_NAME,
                self.request,
                event=self.EVENT_NAME,
                user=email,
            )
        else:
            # No user found ? the form data wasn't really valid
            log(
                LOGGER_NAME,
                self.request,
                event=self.EVENT_NAME,
                email=email,
            )
        return super().form_valid(form)


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
        next_url = self.get_success_url()
        log(
            LOGGER_NAME,
            self.request,
            event=event_name,
            next_url=next_url,
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
            "otp": {
                "url": reverse("accounts:otp_devices"),
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


class OtpDevices(MyAccountMixin, TemplateView):
    template_name = "otp_devices.html"

    def post(self, request, *args, **kwargs):
        if request.POST.get("action") == "new":
            device = create_new_totp_device(request)
            return HttpResponseRedirect(reverse("accounts:otp_confirm_device", kwargs={"device_id": device.pk}))

        if device_id := request.POST.get("delete-device"):
            device = get_object_or_404(TOTPDevice.objects.filter(user=request.user), pk=device_id)
            if device != request.user.otp_device:
                messages.success(request, "L’appareil a été supprimé.")
                log(
                    LOGGER_NAME,
                    self.request,
                    user=self.request.user.email,
                    event="delete_otp_device",
                    device=device.pk,
                )
                device.delete()
            else:
                messages.error(request, "Impossible de supprimer l’appareil qui a été utilisé pour se connecter.")
            return self.get(request)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["devices"] = sorted(devices_for_user(self.request.user), key=lambda device: device.created_at)
        return context


class OtpConfirmDevice(MyAccountMixin, FormView):
    form_class = forms.ConfirmTOTPDeviceForm
    template_name = "otp_confirm_device.html"
    EVENT_NAME = "confirm_otp_device"

    def setup(self, request, device_id, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.device = get_object_or_404(TOTPDevice.objects.filter(user=request.user, confirmed=False), pk=device_id)

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"device": self.device}

    def form_valid(self, form):
        self.device.confirmed = True
        self.device.name = form.cleaned_data["name"]
        self.device.save(update_fields=["name", "confirmed"])
        messages.success(self.request, "Votre nouvel appareil est confirmé", extra_tags="toast")
        log(
            LOGGER_NAME,
            self.request,
            user=self.request.user.email,
            event=self.EVENT_NAME,
            device=self.device.pk,
        )
        # Mark the user as verified
        otp_login(self.request, self.device)
        return super().form_valid(form)

    def get_success_url(self):
        return get_next_url(self.request, fallback_url=reverse("accounts:otp_devices"))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["otp_secret"] = b32encode(self.device.bin_key).decode()
        # Generate svg data uri qrcode
        context["qrcode"] = segno.make(self.device.config_url).svg_data_uri()
        context["otp_verified"] = False
        return context


class VerifyOTPView(FormView):
    template_name = "verify_otp.html"
    form_class = forms.VerifyOTPForm
    EVENT_NAME = "verify_otp_device"

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.request.user}

    def form_valid(self, form):
        otp_login(self.request, self.request.user.otp_device)
        log(
            LOGGER_NAME,
            self.request,
            user=self.request.user.email,
            event=self.EVENT_NAME,
            device=self.request.user.otp_device.pk,
        )
        return super().form_valid(form)

    def get_success_url(self):
        return get_next_url(self.request)
