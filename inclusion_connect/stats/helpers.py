from functools import lru_cache

from django.utils import timezone

from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.stats.models import Stats
from inclusion_connect.utils.oidc import oidc_params


@lru_cache
def get_application(request, next_url=None):
    try:
        return Application.objects.get(client_id=oidc_params(request, next_url)["client_id"])
    except KeyError:
        return None


def account_action(user, action, request, next_url=None):
    if application := get_application(request, next_url):
        Stats.objects.get_or_create(
            user=user,
            application=application,
            date=timezone.localdate().replace(day=1),
            action=action,
        )
