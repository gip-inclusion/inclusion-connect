import pytest
from django.test.client import Client


pytest.register_assert_rewrite("tests.asserts", "tests.helpers")


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Automatically add pytest db marker if needed."""
    for item in items:
        markers = {marker.name for marker in item.iter_markers()}
        if "no_django_db" not in markers and "django_db" not in markers:
            item.add_marker(pytest.mark.django_db)


class NoInlineClient(Client):
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


@pytest.fixture
def client(django_capture_on_commit_callbacks):
    class ExecuteOnCommitCallbacksClient(Client):
        def request(self, **request):
            with django_capture_on_commit_callbacks(execute=True):
                return super().request(**request)

    class InclusionConnectTestClient(ExecuteOnCommitCallbacksClient, NoInlineClient):
        pass

    return InclusionConnectTestClient()
