from django.conf import settings
from django.contrib import auth
from django.contrib.sessions.models import Session
from django.urls import reverse
from django.utils import timezone
from django_otp import user_has_device
from django_otp.plugins.otp_totp.models import TOTPDevice

from inclusion_connect.logging import log


LOGGER_NAME = "inclusion_connect.auth"


def delete_user_sessions(user):
    """Delete every active Django session belonging to ``user``.

    Shared by the OIDC RP-initiated logout and the SAML local SLO so both protocols
    terminate the IC session the same way (all of the user's sessions, not just the
    current one).
    """
    for session in Session.objects.filter(expire_date__gte=timezone.now()):
        if session.get_decoded().get("_auth_user_id") == str(user.pk):
            session.delete()


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
        log(
            LOGGER_NAME,
            request,
            user=request.user.email,
            event="create_otp_device",
            device=device.pk,
        )
    return device


def next_action_url(request):
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
    next_url = next_action_url(request)
    if next_url:
        return next_url
    session_next_url = request.session.pop("next_url", None)
    return session_next_url or fallback_url or reverse("accounts:home")
