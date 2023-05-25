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


@pytest.fixture
def client(django_capture_on_commit_callbacks):
    class ExecuteOnCommitCallbacksClient(Client):
        def request(self, **request):
            with django_capture_on_commit_callbacks(execute=True):
                return super().request(**request)

    return ExecuteOnCommitCallbacksClient()
