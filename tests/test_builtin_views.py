from django.urls import reverse

from tests.conftest import Client


def test_csrf_view(snapshot):
    client = Client(enforce_csrf_checks=True)
    response = client.post(reverse("accounts:login"), {"username": "doesnot", "password": "matter"})
    assert str(response.content.decode()) == snapshot
