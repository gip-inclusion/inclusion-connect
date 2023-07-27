from django.urls import reverse


def test_homepage(client, snapshot):
    response = client.get(reverse("homepage"))
    assert str(response.content.decode()) == snapshot
