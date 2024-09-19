from bs4 import BeautifulSoup
from django.urls import reverse

from tests.users.factories import UserFactory


def test_new_password_display(client, snapshot):
    client.force_login(UserFactory())
    response = client.get(reverse("accounts:change_password"))
    soup = BeautifulSoup(response.content, "html5lib", from_encoding=response.charset)
    form_group = soup.find("label", attrs={"for": "id_new_password1"}).parent
    assert str(form_group) == snapshot(name="new password has instructions")
