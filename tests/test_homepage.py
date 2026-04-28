from django.urls import reverse

from tests.helpers import parse_response_to_soup, pretty_indented


def test_homepage(client, snapshot):
    response = client.get(reverse("homepage"))
    assert pretty_indented(parse_response_to_soup(response)) == snapshot
