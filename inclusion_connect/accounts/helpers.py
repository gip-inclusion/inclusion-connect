import logging
from functools import partial

from django.conf import settings
from django.contrib import auth
from django.db import transaction
from django.urls import reverse
from django_otp import user_has_device
from django_otp.plugins.otp_totp.models import TOTPDevice

from inclusion_connect.logging import log_data


logger = logging.getLogger("inclusion_connect.auth")


def login(request, user, backend=settings.DEFAULT_AUTH_BACKEND):
    """
    Log the user and preserve the next url (as login again flushes the session)
    """
    next_url = request.session.get("next_url")
    auth.login(request, user, backend=backend)
    if next_url:
        request.session["next_url"] = next_url


def create_new_totp_device(request):
    """
    Return the existing unconfirmed device for the user, or create a new one
    """
    device, created = TOTPDevice.objects.get_or_create(user=request.user, confirmed=False)

    if created:
        log = log_data(request)
        log["user"] = request.user.email
        log["event"] = "create_otp_device"
        log["device"] = device.pk
        transaction.on_commit(partial(logger.info, log))
    return device


def required_action_url(request):
    if not request.user.is_verified():
        if user_has_device(request.user):
            return reverse("accounts:verify_otp")

        device = create_new_totp_device(request)
        return reverse("accounts:otp_confirm_device", args=(device.pk,))
    if request.user.password_is_temporary:
        return reverse("accounts:change_temporary_password")
    if request.user.password_is_too_weak:
        return reverse("accounts:change_weak_password")
    return None


def get_next_url(request, fallback_url=None):
    if not request.user.is_authenticated:
        return None
    next_url = required_action_url(request)
    if next_url:
        return next_url
    session_next_url = request.session.pop("next_url", None)
    user_next_url = request.user.pop_next_redirect_uri()
    return session_next_url or user_next_url or fallback_url or reverse("accounts:home")
