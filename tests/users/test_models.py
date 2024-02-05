import pytest
from django.db import IntegrityError
from django.utils import timezone
from freezegun import freeze_time

from tests.users.factories import UserFactory


def test_can_have_multiple_users_with_blank_email():
    UserFactory.create_batch(2, email="")


def test_save_next_redirect_uri():
    user = UserFactory()
    with freeze_time("2023-06-02 12:40:12"):
        now = timezone.now()
        user.save_next_redirect_uri("toto")
    user.refresh_from_db()
    assert user.next_redirect_uri == "toto"
    assert user.next_redirect_uri_stored_at == now


def test_pop_next_redirect_uri_empty():
    user = UserFactory()
    assert user.pop_next_redirect_uri() is None


def test_pop_next_redirect_uri_too_late():
    user = UserFactory()
    with freeze_time("2023-06-02 12:40:12"):
        user.save_next_redirect_uri("toto")
    with freeze_time("2023-06-03 12:40:12.001"):
        assert user.pop_next_redirect_uri() is None
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assert user.next_redirect_uri_stored_at is None


def test_pop_next_redirect_uri():
    user = UserFactory()
    with freeze_time("2023-06-02 12:40:12"):
        user.save_next_redirect_uri("toto")
    with freeze_time("2023-06-03 12:40:12"):
        assert user.pop_next_redirect_uri() == "toto"
    user.refresh_from_db()
    assert user.next_redirect_uri is None
    assert user.next_redirect_uri_stored_at is None


def test_federation_sub_is_unique():
    kwargs = {"federation": "peama", "federation_sub": "uniq"}
    UserFactory(**kwargs)
    with pytest.raises(
        IntegrityError,
        match=r'^duplicate key value violates unique constraint "unique_sub_per_federation"',
    ):
        UserFactory(**kwargs)
