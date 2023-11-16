from django.contrib.auth.hashers import PBKDF2PasswordHasher

from inclusion_connect.keycloak_compat.hashers import KeycloakPasswordHasher
from tests.users.factories import UserFactory


def test_password_hasher(client):
    password = "RdaRfqP7Y89vy2"
    hashed_password = "$".join(
        [
            "keycloak-pbkdf2-sha256",
            "27500",
            "Td6XuopYK6JNfUnIlqYMOQ==",
            "ZXVC08Hf4jBOoYzVoNWYjQijsMC2oc/OUa9LciiIJ/1XHPF/qPiY1DqwLLDN2hYFmf/1kApkveD8/Pr7GVqjgw==",
        ]
    )
    user = UserFactory(password=hashed_password)
    assert user.password == hashed_password

    assert KeycloakPasswordHasher().verify(password=password, encoded=hashed_password)

    client.login(email=user.email, password=password)

    user.refresh_from_db()
    assert user.password != hashed_password
    assert PBKDF2PasswordHasher().verify(password, encoded=user.password)
