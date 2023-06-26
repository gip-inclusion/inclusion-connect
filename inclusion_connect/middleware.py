from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils.cache import add_never_cache_headers
from django.utils.html import format_html

from inclusion_connect.utils.urls import add_url_params


def never_cache(get_response):
    def middleware(request):
        response = get_response(request)
        if request.user.is_authenticated:
            add_never_cache_headers(response)
        return response

    return middleware


def limit_staff_users_to_admin(get_response):
    def middleware(request):
        user = request.user

        if user.is_staff and not request.path.startswith("/admin/"):
            exception = format_html(
                "Les comptes administrateurs n'ont pas accès à cette page.<br>"
                '<a href="{}">Vous pouvez-vous déconnecter ici.</a>',
                add_url_params(reverse("admin:logout"), {"next": request.get_full_path()}),
            )
            raise PermissionDenied(exception)

        return get_response(request)

    return middleware
