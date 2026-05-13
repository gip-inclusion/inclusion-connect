import pytest
from django.test import TestCase, client as django_client
from django_otp import DEVICE_ID_SESSION_KEY
from django_otp.plugins.otp_totp.models import TOTPDevice


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


# Singleton to enable passing None value
Default = type("Default", (), dict(__repr__=lambda self: "Default"))()


class Client(ExecuteOnCommitCallbacksClient, NoInlineClient):
    def force_login(self, user, device=Default, backend=None):
        super().force_login(user, backend=backend)
        if device is not None:
            if device == Default:
                device = TOTPDevice.objects.filter(user=user).first() or TOTPDevice.objects.create(user=user)
            session = self.session
            session[DEVICE_ID_SESSION_KEY] = device.persistent_id
            session.save()


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
