from urllib.parse import parse_qsl, urlparse

from django.utils.http import url_has_allowed_host_and_scheme, urlencode


def add_url_params(url: str, params: dict[str, str]) -> str:
    """Add GET params to provided URL being aware of existing.

    :param url: string of target URL
    :param params: dict containing requested params to be added
    :return: string with updated URL

    >> url = 'http://localhost:8000/login/activate_siae_staff_account?next_url=%2Finvitations
    >> new_params = {'test': 'value' }
    >> add_url_params(url, new_params)
    'http://localhost:8000/login/activate_siae_staff_account?next_url=%2Finvitations&test=value
    """

    # Remove params with None values
    params = {key: params[key] for key in params if params[key] is not None}
    url_parts = urlparse(url)
    query = get_url_params(url)
    query.update(params)

    new_url = url_parts._replace(query=urlencode(query)).geturl()

    return new_url


def get_url_params(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlparse(url).query))


def is_inclusion_connect_url(request, url):
    return url_has_allowed_host_and_scheme(url, request.get_host(), require_https=request.is_secure())
