from tests.users.factories import UserFactory


def test_can_have_multiple_users_with_blank_email():
    UserFactory.create_batch(2, email="")
