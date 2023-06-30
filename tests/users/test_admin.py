import datetime
import logging

from django.contrib.auth.models import Group, Permission
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pytest_django.asserts import assertContains, assertNotContains, assertQuerySetEqual, assertRedirects

from inclusion_connect.oidc_federation.enums import Federation
from inclusion_connect.users.models import EmailAddress, User
from tests.helpers import assertRecords, parse_response_to_soup
from tests.users.factories import UserFactory


class TestUserAdmin:
    def test_admin_detail(self, client):
        user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(user)
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assert response.status_code == 200

    def test_search_by_email_address(self, client, snapshot):
        admin = UserFactory(
            first_name="Admin",
            last_name="Istrator",
            email="administrator@theadmin.com",
            is_staff=True,
            is_superuser=True,
        )
        alice_id = "11111111-1111-1111-1111-111111111111"
        bob_id = "22222222-2222-2222-2222-222222222222"
        charlie_chaplin_id = "33333333-3333-3333-3333-333333333333"
        charlie_dupont_id = "44444444-4444-4444-4444-444444444444"
        alice_not_verified = UserFactory(username=alice_id, first_name="Alice", last_name="Adam", email="")
        EmailAddress.objects.create(user=alice_not_verified, email="a.a@mailinator.com")
        UserFactory(
            username=bob_id,
            first_name="Bob",
            last_name="Bear",
            email="b.b@mailinator.com",
        )
        charlie_chaplin = UserFactory(
            username=charlie_chaplin_id,
            first_name="Charlie",
            last_name="Chaplin",
            email="charlie.chaplin@mailinator.com",
        )
        # Charlie Chaplin is in the process of changing changing their email.
        EmailAddress.objects.create(user=charlie_chaplin, email="c.chaplin@mailinator.com")
        UserFactory(
            username=charlie_dupont_id,
            first_name="Charlie",
            last_name="Dupont",
            email="c.dupont@mailinator.com",
        )

        client.force_login(admin)
        result_id = "#result_list"

        def search(terms):
            response = client.get(reverse("admin:users_user_changelist"), {"q": terms})
            assert response.status_code == 200
            return str(parse_response_to_soup(response, selector=result_id))

        # Email not verified.
        assert search("a.a") == snapshot(name="a.a → only Alice")
        # Email verified.
        assert search("b.b") == snapshot(name="b.b → only Bob")
        assert search("mAiLiNaToR") == snapshot(name="mAiLiNaToR → all users, no duplicates, case insensitive")
        assert search(".chaplin") == snapshot(name=".chaplin → only Charlie Chaplin")
        assert search("c.") == snapshot(name="c. → both Charlie")
        assert search("charlie chaplin") == snapshot(name="charlie chaplin → only Charlie Chaplin")
        # Uses AND as a connector, searching both Alice and Bob yields no results.
        assertNotContains(client.get(reverse("admin:users_user_changelist"), {"q": "alice bob"}), result_id)
        # Using exact search with quotes.
        assertNotContains(client.get(reverse("admin:users_user_changelist"), {"q": "'charlie c'"}), result_id)

    def test_admin_add(self, caplog, client):
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        password = "V€r¥--$3©®€7"
        response = client.post(
            reverse("admin:users_user_add"),
            {
                "password1": password,
                "password2": password,
                "email_addresses-TOTAL_FORMS": "0",
                "email_addresses-INITIAL_FORMS": "0",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
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
        assert user.email_addresses.exists() is False
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
                "must_reset_password": "off",
                "first_name": "Manuel",
                "last_name": "Calavera",
                "email": "manny.calavera@mailinator.com",
                "is_active": "on",
                "is_staff": "on",
                "email_addresses-TOTAL_FORMS": "0",
                "email_addresses-INITIAL_FORMS": "0",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
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
                        "email_changed": "manny.calavera@mailinator.com",
                    },
                )
            ],
        )

        staff_group = Group.objects.get(name="support")
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "must_reset_password": "off",
                "first_name": "Manuel",
                "last_name": "Calavera",
                "email": "manny.calavera@mailinator.com",
                "is_active": "on",
                "is_staff": "on",
                "groups": staff_group.pk,
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
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
                        "groups": {"added": {1: "support"}},
                    },
                )
            ],
        )

    @freeze_time("2023-05-12T14:42:03")
    def test_confirm_email(self, caplog, client):
        user = UserFactory(email="")
        email_address = EmailAddress.objects.create(email="me@mailinator.com", user=user)
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "",
                "confirm_email": "on",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": email_address.pk,
                "email_addresses-0-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, url)
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        email_address = user.email_addresses.get()
        assert email_address.email == "me@mailinator.com"
        assert email_address.user_id == user.pk
        assert email_address.verified_at == datetime.datetime(2023, 5, 12, 14, 42, 3, tzinfo=datetime.timezone.utc)
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
                        "email_confirmed": "me@mailinator.com",
                    },
                )
            ],
        )

    @freeze_time("2023-05-12T14:42:03")
    def test_confirm_other_email(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        email_address = EmailAddress.objects.create(email="other@mailinator.com", user=user)
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "confirm_email": "on",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "2",
                "email_addresses-INITIAL_FORMS": "2",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "email_addresses-1-id": email_address.pk,
                "email_addresses-1-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, url)
        user.refresh_from_db()
        assert user.email == "other@mailinator.com"
        email_address = user.email_addresses.get()
        assert email_address.email == "other@mailinator.com"
        assert email_address.user_id == user.pk
        assert email_address.verified_at == datetime.datetime(2023, 5, 12, 14, 42, 3, tzinfo=datetime.timezone.utc)
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
                        "email_confirmed": "other@mailinator.com",
                    },
                )
            ],
        )

    @freeze_time("2023-05-12T14:42:03")
    def test_update_verified_email(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "other@mailinator.com",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, url)
        user.refresh_from_db()
        assert user.email == "other@mailinator.com"
        email_address = user.email_addresses.get()
        assert email_address.email == "other@mailinator.com"
        assert email_address.user_id == user.pk
        assert email_address.verified_at == datetime.datetime(2023, 5, 12, 14, 42, 3, tzinfo=datetime.timezone.utc)
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
                        "email_changed": "other@mailinator.com",
                    },
                )
            ],
        )

    @freeze_time("2023-05-12T14:42:03")
    def test_dont_update_verified_email_and_confirm_another(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        email_address = EmailAddress.objects.create(email="other@mailinator.com", user=user)
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "new@mailinator.com",
                "confirm_email": "on",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "2",
                "email_addresses-INITIAL_FORMS": "2",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "email_addresses-1-id": email_address.pk,
                "email_addresses-1-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assert (
            response.context["errors"][0][0]
            == "Vous ne pouvez pas à la fois modifier l'email validé, et confirmer un email"
        )
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        assert user.email_addresses.count() == 2
        assert verified_email_address.email == "me@mailinator.com"
        assert verified_email_address.user_id == user.pk
        assert verified_email_address.verified_at == datetime.datetime(
            2023, 5, 12, 14, 42, 3, tzinfo=datetime.timezone.utc
        )
        assert email_address.email == "other@mailinator.com"
        assert email_address.user_id == user.pk
        assert email_address.verified_at is None
        assertRecords(caplog, [])

    @freeze_time("2023-05-12T14:42:03")
    def test_update_verified_email_and_confirm_the_same_email(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        email_address = EmailAddress.objects.create(email="other@mailinator.com", user=user)
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "other@mailinator.com",
                "confirm_email": "on",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "2",
                "email_addresses-INITIAL_FORMS": "2",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "email_addresses-1-id": email_address.pk,
                "email_addresses-1-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assertRedirects(response, url)
        user.refresh_from_db()
        assert user.email == "other@mailinator.com"
        email_address = user.email_addresses.get()
        assert email_address.email == "other@mailinator.com"
        assert email_address.user_id == user.pk
        assert email_address.verified_at == datetime.datetime(2023, 5, 12, 14, 42, 3, tzinfo=datetime.timezone.utc)
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
                        "email_confirmed": "other@mailinator.com",
                    },
                )
            ],
        )

    @freeze_time("2023-05-12T14:42:03")
    def test_dont_erase_email(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        client.force_login(UserFactory(is_superuser=True, is_staff=True))
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "",
                "confirm_email": "on",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assert response.context["errors"][0][0] == "Vous ne pouvez pas supprimer l'adresse e-mail de l'utilsateur."
        user.refresh_from_db()
        assert user.email == "me@mailinator.com"
        assertRecords(caplog, [])

    @freeze_time("2023-05-12T14:42:03")
    def test_dont_crash_if_new_email_is_invalid(self, caplog, client):
        user = UserFactory(email="me@mailinator.com")
        verified_email_address = user.email_addresses.get()
        client.force_login(UserFactory(is_superuser=True, is_staff=True))
        url = reverse("admin:users_user_change", kwargs={"object_id": user.pk})
        response = client.post(
            url,
            data={
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": "bad_email",
                "is_active": "on",
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": verified_email_address.pk,
                "email_addresses-0-user": user.pk,
                "linked_applications-TOTAL_FORMS": "0",
                "linked_applications-INITIAL_FORMS": "0",
                "linked_applications-MIN_NUM_FORMS": "0",
                "linked_applications-MAX_NUM_FORMS": "0",
                "_continue": "Enregistrer+et+continuer+les+modifications",
            },
        )
        assert response.status_code == 200
        assert response.context["errors"][0][0] == "Saisissez une adresse de courriel valide."
        assert user.email == "me@mailinator.com"
        assertRecords(caplog, [])

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
        assert user.must_reset_password
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
            data={"password1": password, "password2": password},
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
        assert user.must_reset_password is True

    def test_support_staff_cannot_elevate_privileges(self, client):
        staff_user = UserFactory(is_staff=True, email_address=False)
        email_address = EmailAddress.objects.create(
            user=staff_user, email=staff_user.email, verified_at=timezone.now()
        )
        staff_group = Group.objects.get(name="support")
        staff_user.groups.set([staff_group])
        client.force_login(staff_user)
        response = client.post(
            reverse("admin:users_user_change", args=(staff_user.pk,)),
            data={
                "must_reset_password": "off",
                "first_name": "Kiddy",
                "last_name": "Script",
                "email": staff_user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": "",  # Can’t modify groups.
                "user_permissions": [Permission.objects.order_by("?").first()],
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": email_address.pk,
                "email_addresses-0-user": staff_user.pk,
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
        user = UserFactory(email_address=False)
        email_address = EmailAddress.objects.create(user=user, email=user.email, verified_at=timezone.now())
        client.force_login(staff_user)
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "must_reset_password": "off",
                "first_name": "Kiddy",
                "last_name": "Script",
                "email": user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": staff_group.pk,
                "user_permissions": [Permission.objects.order_by("?").first()],
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": email_address.pk,
                "email_addresses-0-user": user.pk,
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
        user = UserFactory(email_address=False)
        email_address = EmailAddress.objects.create(user=user, email=user.email, verified_at=timezone.now())
        client.force_login(UserFactory(is_staff=True, is_superuser=True))
        response = client.post(
            reverse("admin:users_user_change", args=(user.pk,)),
            data={
                "must_reset_password": "off",
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
                "is_active": "on",
                "is_staff": "on",
                "is_superuser": "on",
                "groups": staff_group.pk,
                "email_addresses-TOTAL_FORMS": "1",
                "email_addresses-INITIAL_FORMS": "1",
                "email_addresses-MIN_NUM_FORMS": "0",
                "email_addresses-MAX_NUM_FORMS": "0",
                "email_addresses-0-id": email_address.pk,
                "email_addresses-0-user": user.pk,
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
            '<select name="groups" id="id_groups" multiple class="selectfilter" data-field-name="groupes" '
            'data-is-stacked="0">',
            count=1,
        )
        assertContains(
            response,
            '<select name="user_permissions" id="id_user_permissions" multiple class="selectfilter" '
            'data-field-name="permissions de l’utilisateur" data-is-stacked="0">',
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

        result_id = '[class*="field-must_reset_password"]'

        def get_password_form_field():
            response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
            assert response.status_code == 200
            return str(parse_response_to_soup(response, selector=result_id))

        client.force_login(user)
        assert get_password_form_field() == snapshot(name="normal password")

        user.must_reset_password = True
        user.save()
        assert get_password_form_field() == snapshot(name="temporary password")

    def test_admin_federated_user(self, client, snapshot):
        admin_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(admin_user)
        user = UserFactory(
            first_name="John",
            last_name="Doe",
            email="john@doe.net",
            username="11111111-1111-1111-1111-111111111111",
            federation=Federation.PEAMA,
            federation_sub="id_pe",
            federation_data={"site_pe": "aaa", "structure_pe": 111},
        )
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assertNotContains(response, "field-must_reset_password")
        assert str(parse_response_to_soup(response, selector='[class="form-row field-federation"]')) == snapshot(
            name="federation"
        )
        assert str(parse_response_to_soup(response, selector='[class*="field-federation_sub"]')) == snapshot(
            name="federation_sub"
        )
        assert str(parse_response_to_soup(response, selector='[class*="field-federation_data"]')) == snapshot(
            name="federation_data"
        )
