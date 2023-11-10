from django.conf import settings
from django.http import HttpResponseRedirect
from django.urls import reverse


def required_action_url(user):
    if user.must_accept_terms:
        return reverse("accounts:accept_terms")
    if user.must_reset_password:
        return reverse("accounts:change_temporary_password")
    if user.new_email_already_used:
        return reverse("accounts:warn_new_email_already_used")
    return None


def post_login_actions(get_response):
    def middleware(request):
        user = request.user

        whitelisted_urls = [reverse("homepage"), reverse("oauth2_provider:rp-initiated-logout")] + [
            reverse(f"keycloak_compat_{realm}:logout") for realm in settings.KEYCLOAK_REALMS
        ]

        path_is_whitelisted = request.path in whitelisted_urls

        if user.is_authenticated and user.is_staff is False and path_is_whitelisted is False:
            next_action_url = required_action_url(user)
            if next_action_url and not request.path == next_action_url:
                return HttpResponseRedirect(next_action_url)

        return get_response(request)

    return middleware
