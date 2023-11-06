import logging

from django.core.exceptions import PermissionDenied
from django.urls import reverse
from django.utils.cache import add_never_cache_headers
from django.utils.html import format_html

from inclusion_connect.logging import log_data
from inclusion_connect.utils.urls import add_url_params


logger = logging.getLogger("keycloak_compat")


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


def log_keycloak_compat(get_response):
    def middleware(request):
        response = get_response(request)
        if request.path.startswith("/realms"):
            log = log_data(request)
            if "application" not in log and request.GET.get("client_id"):
                log["application"] = request.GET.get("client_id")
            log["url"] = request.path
            logger.warning(log)
        return response

    return middleware
