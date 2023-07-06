import datetime

from freezegun import freeze_time
from pytest_django.asserts import assertQuerySetEqual

from inclusion_connect.stats.helpers import account_action
from inclusion_connect.stats.models import Actions, Stats
from tests.oidc_overrides.factories import ApplicationFactory
from tests.users.factories import UserFactory


def test_stats(mocker):
    application_1 = ApplicationFactory(client_id="00000000-0000-0000-0000-000000000000")
    application_2 = ApplicationFactory(client_id="11111111-1111-1111-1111-111111111111")
    user = UserFactory()

    with freeze_time("2023-04-27 14:06"):
        mocker.patch("inclusion_connect.stats.helpers.get_application", return_value=application_1)
        account_action(user, Actions.LOGIN, None)

    with freeze_time("2023-04-27 14:07"):
        mocker.patch("inclusion_connect.stats.helpers.get_application", return_value=application_2)
        account_action(user, Actions.LOGIN, None)

    with freeze_time("2023-04-27 14:08"):
        mocker.patch("inclusion_connect.stats.helpers.get_application", return_value=application_1)
        account_action(user, Actions.LOGIN, None)
    with freeze_time("2023-05-01 00:08"):
        mocker.patch("inclusion_connect.stats.helpers.get_application", return_value=application_1)
        account_action(user, Actions.LOGIN, None)

    assertQuerySetEqual(
        Stats.objects.values_list("date", "user", "application", "action").order_by("date", "application__client_id"),
        [
            (datetime.date(2023, 4, 1), user.pk, application_1.pk, "login"),
            (datetime.date(2023, 4, 1), user.pk, application_2.pk, "login"),
            (datetime.date(2023, 5, 1), user.pk, application_1.pk, "login"),
        ],
    )
