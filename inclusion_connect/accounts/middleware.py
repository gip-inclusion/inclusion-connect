from django.http import HttpResponseRedirect
from django.urls import reverse
from django_otp import user_has_device


def required_action_url(request):
    if not request.user.is_verified():
        if user_has_device(request.user):
            return reverse("accounts:verify_otp")

        # Retreive existing unconfirmed device, or create one
        from inclusion_connect.accounts.helpers import create_new_totp_device  # noqa

        device = create_new_totp_device(request)
        return reverse("accounts:otp_confirm_device", args=(device.pk,))
    if request.user.password_is_temporary:
        return reverse("accounts:change_temporary_password")
    if request.user.password_is_too_weak:
        return reverse("accounts:change_weak_password")
    return None


def post_login_actions(get_response):
    def middleware(request):
        user = request.user

        whitelisted_urls = [reverse("index"), reverse("oauth2_provider:rp-initiated-logout")]
        path_is_whitelisted = request.path in whitelisted_urls

        if user.is_authenticated and path_is_whitelisted is False:
            next_action_url = required_action_url(request)
            if next_action_url and not request.path == next_action_url:
                return HttpResponseRedirect(next_action_url)

        return get_response(request)

    return middleware
