from django.http import HttpResponseRedirect
from django.urls import reverse

from inclusion_connect.accounts.helpers import next_action_url


def post_login_actions(get_response):
    def middleware(request):
        user = request.user

        whitelisted_urls = [reverse("index"), reverse("oauth2_provider:rp-initiated-logout")]
        path_is_whitelisted = request.path in whitelisted_urls

        if user.is_authenticated and path_is_whitelisted is False:
            next_url = next_action_url(request)
            if next_url and not request.path == next_url:
                return HttpResponseRedirect(next_url)

        return get_response(request)

    return middleware
