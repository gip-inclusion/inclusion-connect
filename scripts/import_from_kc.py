#!/usr/bin/env python3

import os
import pathlib
import sys


sys.path.append(str(pathlib.Path(__file__).parent.parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "inclusion_connect.settings.dev")
import django


django.setup()

import datetime
import json
from collections import defaultdict

import psycopg2
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from inclusion_connect.keycloak_compat.models import JWTHashSecret
from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.users.models import EmailAddress, User, UserApplicationLink


# Don't keep old users that did not validate their email after X days
UNVERIFED_USERS_DAYS_CUTOFF = 2
REALMS = ["inclusion-connect", "Demo"]

KC_DBNAME = os.getenv("KC_DBNAME")
KC_HOST = os.getenv("KC_HOST")
KC_PORT = os.getenv("KC_PORT")
KC_PASSWORD = os.getenv("KC_PASSWORD")
KC_USER = os.getenv("KC_USER")


def parse_keycloak_dt(value):
    return datetime.datetime.fromtimestamp(value / 1000, datetime.UTC)


class KeyCloakCursor:
    def __init__(self):
        self.cursor = None
        self.connection = None

    def __enter__(self):
        self.connection = psycopg2.connect(
            host=KC_HOST,
            dbname=KC_DBNAME,
            port=KC_PORT,
            password=KC_PASSWORD,
            user=KC_USER,
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=5,
            keepalives_count=5,
        )
        self.connection.autocommit = True
        self.cursor = self.connection.cursor()
        return self.cursor

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()


with KeyCloakCursor() as cursor:
    # Secrets
    cursor.execute(
        """
        SELECT realm.name AS "realm", component_config.value AS "secret"
        FROM component
        INNER JOIN component_config ON component_config.component_id=component.id
        INNER JOIN realm ON component.parent_id=realm.id
        WHERE component.name='hmac-generated' AND component_config.name='secret'
        """
    )
    jwt_secrets_data = cursor.fetchall()

    # Users
    cursor.execute(
        """
        SELECT user_entity.id, username, email, first_name, last_name, email_verified, created_timestamp, realm.name
        FROM user_entity
        INNER JOIN realm ON user_entity.realm_id = realm.id
        """
    )
    users_data = cursor.fetchall()

    # required actions
    cursor.execute(
        """
        SELECT user_id, required_action
        FROM user_required_action
        """
    )
    actions = cursor.fetchall()
    users_must_accept_terms = []
    users_must_verify_email = []
    users_must_reset_password = []
    action_to_userlist = {
        "VERIFY_EMAIL": users_must_verify_email,
        "terms_and_conditions": users_must_accept_terms,
        "UPDATE_PASSWORD": users_must_reset_password,
    }
    for user_id, required_action in actions:
        action_to_userlist[required_action].append(user_id)

    # credentials_data
    cursor.execute(
        """
        SELECT user_id, secret_data, credential_data, created_date
        FROM credential
        ORDER BY created_date
        """
    )
    credentials_data = cursor.fetchall()
    credentials = {}
    for user_id, secret_data, credential_data, created_date in credentials_data:
        decoded_secret_data = json.loads(secret_data)
        secret = decoded_secret_data["value"]
        salt = decoded_secret_data["salt"]
        decoded_credential_data = json.loads(credential_data)
        iterations = decoded_credential_data["hashIterations"]
        # Overwrite previous credentials if it exists
        credentials[user_id] = "$".join(["keycloak-pbkdf2-sha256", str(iterations), salt, secret])

    # application links
    cursor.execute(
        """
        SELECT user_id, client_id, MAX(event_time)
        FROM event_entity
        WHERE type = 'LOGIN'
        GROUP BY user_id, client_id
        """
    )
    app_links_data = cursor.fetchall()
    users_app_links = defaultdict(list)
    for user_id, client_id, event_time in app_links_data:
        users_app_links[user_id].append([client_id, parse_keycloak_dt(event_time)])

    users_last_login = {}
    for user_id, application_last_logins in users_app_links.items():
        users_last_login[user_id] = max([event_time for client_id, event_time in application_last_logins])

    # Applications
    cursor.execute(
        """
        SELECT client_id, secret, client.name, realm.name
        FROM client
        INNER JOIN realm ON client.realm_id = realm.id
        WHERE secret is not NULL
        """
    )
    application_data = cursor.fetchall()

    # Redirect uris
    cursor.execute(
        """
        SELECT client.client_id, redirect_uris.value
        FROM redirect_uris
        INNER JOIN client
        ON client.id = redirect_uris.client_id
        """
    )
    redirect_uris_data = cursor.fetchall()
    redirect_uris = defaultdict(list)
    for client_id, value in redirect_uris_data:
        redirect_uris[client_id].append(value)

applications = {}
for client_id, secret, name, realm_name in application_data:
    if realm_name not in REALMS:
        continue
    applications[client_id] = Application(
        client_id=client_id,
        client_type="confidential",
        authorization_grant_type="authorization-code",
        client_secret=secret,
        name=name,
        algorithm="RS256",
        redirect_uris=" ".join(redirect_uris[client_id]),
        post_logout_redirect_uris=" ".join(redirect_uris[client_id]),
    )

users = []
email_addresses = []
app_links = []
for user_id, username, email, first_name, last_name, email_verified, created_timestamp, realm_name in users_data:
    if realm_name not in REALMS:
        continue
    created_at = parse_keycloak_dt(created_timestamp)
    email_verified = email_verified and not user_id in users_must_verify_email
    if not email_verified and created_at < timezone.now() - datetime.timedelta(days=UNVERIFED_USERS_DAYS_CUTOFF):
        continue
    user = User(
        username=user_id,
        email=email if email_verified else "",
        first_name=first_name,
        last_name=last_name,
        date_joined=created_at,
        last_login=users_last_login.get(user_id),
        password=credentials.get(user_id, ""),
        must_reset_password=user_id in users_must_reset_password,
        terms_accepted_at=None if user_id in users_must_accept_terms else max(created_at, settings.NEW_TERMS_DATE),
    )
    email_addresses.append(EmailAddress(user=user, email=email, verified_at=created_at if email_verified else None))

    for client_id, last_login in users_app_links[user_id]:
        if client_id in applications:
            app_links.append(
                UserApplicationLink(
                    user=user,
                    application=applications[client_id],
                    last_login=last_login,
                )
            )

    users.append(user)

jwt_hash_secrets = []
for realm, secret in jwt_secrets_data:
    jwt_hash_secrets.append(JWTHashSecret(realm_id=realm, secret=secret))


# Write in db
with transaction.atomic():
    Application.objects.bulk_create(applications.values())
    User.objects.bulk_create(users)
    EmailAddress.objects.bulk_create(email_addresses)
    UserApplicationLink.objects.bulk_create(app_links)
    JWTHashSecret.objects.bulk_create(jwt_hash_secrets)


print(f"Created {Application.objects.count()} Applications")
print(f"Created {User.objects.count()} Users")
print(f"Created {EmailAddress.objects.count()} EmailAddresses")
print(f"Created {UserApplicationLink.objects.count()} UserApplicationLinks")
print(f"Created {JWTHashSecret.objects.count()} JWTHashSecrets")

# Handle admin users separatly
# Handle users that have accounts in multiple realms ? (in staging) or anly keep demo accounts and realm ?
