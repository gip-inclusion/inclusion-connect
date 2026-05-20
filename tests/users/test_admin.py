import logging

from django.urls import reverse
from pytest_django.asserts import assertContains, assertQuerySetEqual, assertRedirects

from inclusion_connect.users.models import User
from tests.helpers import assertRecords
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
                    {"event": "admin_add", "acting_user": admin_user.email, "user": user.email},
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
                        "acting_user": admin_user.email,
                        "user": user.email,
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
                        "acting_user": admin_user.email,
                        "user": user.email,
                    },
                )
            ],
        )

    def test_admin_password_status_with_usable_password(self, client):
        staff_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(staff_user)

        user = UserFactory()
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assert response.status_code == 200
        assertContains(response, "Mot de passe valide")
        assertContains(response, "Invalider le mot de passe")

    def test_admin_password_status_without_usable_password(self, client):
        staff_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(staff_user)

        user = UserFactory()
        user.set_unusable_password()
        user.save()
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assert response.status_code == 200
        assertContains(response, "Sans mot de passe")
        assertContains(response, "Copier le lien de réinitialisation")

    def test_admin_invalidate_password(self, client):
        staff_user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(staff_user)

        user = UserFactory()
        assert user.has_usable_password()

        invalidate_url = reverse("admin:users_user_invalidate_password", args=[user.pk])
        response = client.get(invalidate_url)
        assert response.status_code == 200
        assertContains(response, "Confirmer")

        response = client.post(invalidate_url)
        assertRedirects(response, reverse("admin:users_user_change", args=[user.pk]))
        user.refresh_from_db()
        assert not user.has_usable_password()

    def test_non_staff_user_cannot_invalidate_password(self, client):
        non_staff_user = UserFactory()
        client.force_login(non_staff_user)
        target_user = UserFactory()
        invalidate_url = reverse("admin:users_user_invalidate_password", args=[target_user.pk])
        response = client.get(invalidate_url)
        assertRedirects(response, reverse("admin:login") + f"?next={invalidate_url}")

    def test_logout(self, client):
        user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(user)
        response = client.post(reverse("admin:logout"))
        assertRedirects(response, reverse("accounts:login"))
