import pytest
from bs4 import BeautifulSoup
from django.test import TestCase, client as django_client


pytest.register_assert_rewrite("tests.asserts", "tests.helpers")


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Automatically add pytest db marker if needed."""
    for item in items:
        markers = {marker.name for marker in item.iter_markers()}
        if "no_django_db" not in markers and "django_db" not in markers:
            item.add_marker(pytest.mark.django_db)


class NoInlineClient(django_client.Client):
    def request(self, **request):
        response = super().request(**request)
        content_type = response["Content-Type"].split(";")[0]
        if content_type == "text/html" and response.content:
            content = response.content.decode(response.charset)
            assert " onclick=" not in content
            assert " onbeforeinput=" not in content
            assert " onbeforeinput=" not in content
            assert " onchange=" not in content
            assert " oncopy=" not in content
            assert " oncut=" not in content
            assert " ondrag=" not in content
            assert " ondragend=" not in content
            assert " ondragenter=" not in content
            assert " ondragleave=" not in content
            assert " ondragover=" not in content
            assert " ondragstart=" not in content
            assert " ondrop=" not in content
            assert " oninput=" not in content
            assert "<script>" not in content
        return response


class ExecuteOnCommitCallbacksClient(django_client.Client):
    def request(self, **request):
        with TestCase.captureOnCommitCallbacks(execute=True):
            return super().request(**request)


class Client(ExecuteOnCommitCallbacksClient, NoInlineClient):
    pass


@pytest.fixture
def client():
    return Client()


@pytest.fixture
def oidc_params():
    return {
        "response_type": "code",
        "client_id": "my_application",
        "redirect_uri": "http://localhost/callback",
        "scope": "openid profile email",
        "state": "state",
        "nonce": "nonce",
    }


def parse_response_to_soup(response, selector=None, no_html_body=False):
    soup = BeautifulSoup(response.content, "html5lib", from_encoding=response.charset or "utf-8")
    if no_html_body:
        # If the provided HTML does not contain <html><body> tags
        # html5lib will always add them around the response:
        # ignore them
        soup = soup.body
    if selector is not None:
        [soup] = soup.select(selector)
    for csrf_token_input in soup.find_all("input", attrs={"name": "csrfmiddlewaretoken"}):
        csrf_token_input["value"] = "NORMALIZED_CSRF_TOKEN"
    if "nonce" in soup.attrs:
        soup["nonce"] = "NORMALIZED_CSP_NONCE"
    for csp_nonce_script in soup.find_all("script", {"nonce": True}):
        csp_nonce_script["nonce"] = "NORMALIZED_CSP_NONCE"
    return soup
