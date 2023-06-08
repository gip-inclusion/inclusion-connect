from bs4 import BeautifulSoup
from django.urls import reverse


def test_new_password_display(client, snapshot):
    response = client.get(reverse("accounts:register"))
    soup = BeautifulSoup(response.content, "html5lib", from_encoding=response.charset)
    form_group = soup.find("label", attrs={"for": "id_password1"}).parent
    assert str(form_group) == snapshot(name="new password has instructions")
