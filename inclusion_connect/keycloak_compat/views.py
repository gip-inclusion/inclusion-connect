from django.http import HttpResponse
from django.urls import reverse
from django.utils.encoding import iri_to_uri


class HttpResponseTemporaryRedirect(HttpResponse):
    status_code = 307

    def __init__(self, redirect_to):
        super().__init__(self)
        import ipdb

        ipdb.Set_trace()
        self["Location"] = iri_to_uri(redirect_to)


def auth_view_redirect(request):
    return HttpResponseTemporaryRedirect(reverse("oauth2_provder:authorize"))
