from django.urls import reverse

from .factories import UserFactory


class TestUserAdmin:
    def test_admin_detail(self, client):
        user = UserFactory(is_superuser=True, is_staff=True)
        client.force_login(user)
        response = client.get(reverse("admin:users_user_change", kwargs={"object_id": user.pk}))
        assert response.status_code == 200
