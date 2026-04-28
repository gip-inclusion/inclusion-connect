import logging

from django.contrib.auth.models import Group, Permission
from django.urls import reverse
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertNotContains, assertQuerySetEqual, assertRedirects

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

        staff_group = Group.objects.get(name="support")
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": "Manuel",
                "last_name": "Calavera",
                "email": "manny.calavera@mailinator.com",
                "is_active": "on",
                "is_staff": "on",
                "groups": staff_group.pk,
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
        assertQuerySetEqual(user.groups.all(), [staff_group])
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
                        "groups": {"added": {staff_group.pk: "support"}},
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

    def test_any_staff_cannot_access_users_admin(self, client):
        staff_user = UserFactory(is_staff=True)
        client.force_login(staff_user)

        user = UserFactory()

        response = client.get(reverse("admin:users_user_changelist"))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_add"))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_change", args=(user.pk,)))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_delete", args=(user.pk,)))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_history", args=(user.pk,)))
        assert response.status_code == 403

        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:auth_user_password_change", args=(user.pk,)),
            data={"password": password},
        )
        assert response.status_code == 403

    def test_support_staff_can_access_users_admin(self, client):
        staff_user = UserFactory(is_staff=True)
        staff_group = Group.objects.get(name="support")
        staff_user.groups.set([staff_group])
        client.force_login(staff_user)

        user = UserFactory()

        response = client.get(reverse("admin:users_user_changelist"))
        assert response.status_code == 200

        response = client.get(reverse("admin:users_user_add"))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_change", args=(user.pk,)))
        assert response.status_code == 200

        response = client.get(reverse("admin:users_user_delete", args=(user.pk,)))
        assert response.status_code == 403

        response = client.get(reverse("admin:users_user_history", args=(user.pk,)))
        assert response.status_code == 200

        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:auth_user_password_change", args=(user.pk,)),
            data={"password": password},
        )
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        user.refresh_from_db()
        assert user.password_is_temporary is True

    def test_support_staff_cannot_edit_superusers(self, client):
        staff_user = UserFactory(is_staff=True)
        staff_group = Group.objects.get(name="support")
        staff_user.groups.set([staff_group])
        client.force_login(staff_user)
        superuser = UserFactory(is_staff=True, is_superuser=True)

        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": superuser.pk}))
        assertNotContains(response, "field-password_is_temporary")
        input_counts = 1  # logout csrf
        input_counts += 1  # user form csrf
        input_counts += 1  # left menu filter
        input_counts += 4  # linked applications inline hidden inputs
        assertContains(response, "<input", input_counts)

        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:auth_user_password_change", args=(superuser.pk,)),
            data={"password": password},
        )
        assert response.status_code == 403

    def test_support_staff_cannot_elevate_privileges(self, client):
        staff_user = UserFactory(is_staff=True)
        staff_group = Group.objects.get(name="support")
        staff_user.groups.set([staff_group])
        client.force_login(staff_user)
        response = client.post(
            reverse("admin:users_user_change", args=(staff_user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": "Kiddy",
                "last_name": "Script",
                "email": staff_user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": "",  # Can’t modify groups.
                "user_permissions": [Permission.objects.order_by("?").first()],
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        # Readonly fields were ignored, hence the 302.
        assertRedirects(response, reverse("admin:users_user_change", args=(staff_user.pk,)))
        staff_user.refresh_from_db()
        assert staff_user.is_staff is True
        assert staff_user.is_superuser is False
        assertQuerySetEqual(staff_user.groups.all(), [staff_group])
        assert staff_user.get_user_permissions() == set()

    def test_superuser_cant_add_privileges_to_regular_users(self, client):
        staff_user = UserFactory(is_staff=True, is_superuser=True)
        staff_group = Group.objects.get(name="support")
        user = UserFactory()
        client.force_login(staff_user)
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": "Kiddy",
                "last_name": "Script",
                "email": user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": staff_group.pk,
                "user_permissions": [Permission.objects.order_by("?").first()],
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        # Readonly fields were ignored, hence the 302.
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)))
        staff_user.refresh_from_db()
        assert user.is_staff is False
        assert user.is_superuser is False
        assertQuerySetEqual(user.groups.all(), [])
        assert user.get_user_permissions() == set()

    def test_superuser_can_promote_user(self, client):
        staff_group = Group.objects.get(name="support")
        user = UserFactory()
        client.force_login(UserFactory(is_staff=True, is_superuser=True))
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "password_is_temporary": "off",
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": staff_group.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        # Readonly fields were ignored, hence the 302.
        assertRedirects(response, reverse("admin:users_user_change", args=(user.pk,)), fetch_redirect_response=False)
        user.refresh_from_db()
        assert user.is_staff is True
        assert user.is_superuser is True
        response = client.get(response.url)
        assertContains(
            response,
            '<select name="groups" data-context="available-source" aria-describedby="id_groups_helptext" '
            'id="id_groups" multiple class="selectfilter" '
            'data-field-name="groupes" data-is-stacked="0">',
            count=1,
        )
        assertContains(
            response,
            '<select name="user_permissions" data-context="available-source" '
            'aria-describedby="id_user_permissions_helptext" id="id_user_permissions" '
            'multiple class="selectfilter" data-field-name="permissions de l’utilisateur" data-is-stacked="0">',
            count=1,
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
