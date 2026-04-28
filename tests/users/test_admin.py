import logging

from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertQuerySetEqual, assertRedirects

from inclusion_connect.users.models import User
from tests.helpers import assertRecords, parse_response_to_soup
from tests.users.factories import UserFactory


class TestUserAdmin:
    def test_admin_detail(self, client):
        user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(user)
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assert response.status_code == 200

    def test_admin_add(self, caplog, client):
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:users_user_add"),
            {
                "password1": password,
                "password2": password,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_save": "Enregistrer",
            },
        )
        user = User.objects.get(is_superuser=False)
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        assert user.email == ""
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "admin_add", "acting_user": admin_user.pk, "user": user.pk},
                )
            ],
        )

        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": "Manuel",
                "last_name": "Calavera",
                "email": "manny.calavera@mailinator.com",
                "is_active": "on",
                "is_staff": "on",
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        user.refresh_from_db()
        assert user.is_staff is True
        assert user.first_name == "Manuel"
        assert user.last_name == "Calavera"
        assert user.email == "manny.calavera@mailinator.com"
        assertQuerySetEqual(user.groups.all(), [])
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "admin_change",
                        "acting_user": admin_user.pk,
                        "user": user.pk,
                        "old_first_name": "",
                        "new_first_name": "Manuel",
                        "old_last_name": "",
                        "new_last_name": "Calavera",
                    },
                )
            ],
        )

        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": "Manuel",
                "last_name": "Calavera",
                "email": "manny.calavera@mailinator.com",
                "is_active": "on",
                "is_staff": "on",
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        user.refresh_from_db()
        assert user.is_staff is True
        assert user.first_name == "Manuel"
        assert user.last_name == "Calavera"
        assert user.email == "manny.calavera@mailinator.com"
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {
                        "event": "admin_change",
                        "acting_user": admin_user.pk,
                        "user": user.pk,
                    },
                )
            ],
        )

    def test_admin_password_update(self, caplog, client, snapshot):
        staff_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(staff_user)

        user = UserFactory(
            first_name="John",
            last_name="Doe",
            email="admin@mailinator.net",
            username="11111111-1111-1111-1111-111111111111",
        )
        response = client.get(reverse("admin:auth_user_password_change", args=(user.pk,)))
        assert str(parse_response_to_soup(response, selector="#user_form")) == snapshot

        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:auth_user_password_change", args=(user.pk,)),
            data={"password": password},
        )
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        user.refresh_from_db()
        assert user.password_is_temporary
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.auth",
                    logging.INFO,
                    {"event": "admin_change_password", "acting_user": staff_user.pk, "user": user.pk},
                )
            ],
        )

    @freeze_time("2023-05-12T16:00:00+02:00")
    def test_admin_detail_password_field(self, client, snapshot):
        user = UserFactory(
            is_superuser=True,
            is_staff=True,
            first_name="Admin",
            last_name="Istrator",
            email="admin@mailinator.net",
            username="11111111-1111-1111-1111-111111111111",
        )

        result_id = '[class*="field-password_is_temporary"]'

        def get_password_form_field():
            response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
            assert response.status_code == 200
            return str(parse_response_to_soup(response, selector=result_id))

        client.force_login(user)
        assert get_password_form_field() == snapshot(name="normal password")

        user.password_is_temporary = True
        user.save()
        assert get_password_form_field() == snapshot(name="temporary password")
