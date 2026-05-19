import logging
from functools import partial

from django.conf import settings
from django.contrib import auth
from django.db import transaction
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
