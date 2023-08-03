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
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.stats.models import Stats
from inclusion_connect.users.models import EmailAddress, User, UserApplicationLink


# Don't keep old users that did not validate their email after X days
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

    # stats
    cursor.execute(
        """
        SELECT user_id
        FROM event_entity
        WHERE type = 'VERIFY_EMAIL'
        """
    )
    users_with_verified_email_action = [a[0] for a in cursor.fetchall()]


applications = {application.client_id: application for application in Application.objects.all()}
existing_users_ids = list(str(a) for a in User.objects.all().values_list("pk", flat=True))
existing_users_email = list(str(a) for a in User.objects.all().values_list("email", flat=True))

users = {}
email_addresses = []
app_links = []
for user_id, username, email, first_name, last_name, email_verified, created_timestamp, realm_name in users_data:
    if user_id in existing_users_ids:
        continue
    if user_id not in users_with_verified_email_action:
        continue
    if realm_name not in REALMS:
        continue
    if email in existing_users_email:
        print(f"Don't keep {email}")
        continue
    created_at = parse_keycloak_dt(created_timestamp)
    email_verified = email_verified and not user_id in users_must_verify_email
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
    email_addresses.append(
        EmailAddress(user=user, email=email, verified_at=created_at if email_verified else None, created_at=created_at)
    )

    for client_id, last_login in users_app_links[user_id]:
        if client_id in applications:
            app_links.append(
                UserApplicationLink(
                    user=user,
                    application=applications[client_id],
                    last_login=last_login,
                )
            )

    users[user_id] = user

with KeyCloakCursor() as cursor:
    # stats
    cursor.execute(
        f"""
        SELECT user_id, client_id, event_time, type
        FROM event_entity
        WHERE type IN ('LOGIN', 'REGISTER')
        AND user_id IN ('{"','".join(users.keys())}')
        """
    )
    stats_data = cursor.fetchall()

stats = []
stats_data_2 = set(
    [
        (user_id, client_id, parse_keycloak_dt(event_time).date().replace(day=1), action)
        for user_id, client_id, event_time, action in stats_data
    ]
)

for user_id, client_id, event_time, action in stats_data_2:
    application = applications.get(client_id)
    user = users.get(user_id)
    if application and user:
        stats.append(
            Stats(
                user=user,
                application=application,
                date=event_time,
                action=action.lower(),
            )
        )

print(f"Created {len(users)} Users")
print(f"Created {len(email_addresses)} EmailAddresses")
print(f"Created {len(app_links)} UserApplicationLinks")
print(f"Created {len(stats)} Stats")

# Write in db
with transaction.atomic():
    User.objects.bulk_create(users.values())
    EmailAddress.objects.bulk_create(email_addresses)
    UserApplicationLink.objects.bulk_create(app_links)
    Stats.objects.bulk_create(stats, ignore_conflicts=True)

print("Sending logs to ES")
with KeyCloakCursor() as cursor:
    cursor.execute(
        f"""
        SELECT event_time, ip_address, user_id, client_id, type
        FROM event_entity
        WHERE type IN ('LOGIN', 'REGISTER')
        AND user_id IN ('{"','".join(users.keys())}')
        """
    )
    stats = cursor.fetchall()

es_config = settings.LOGGING["handlers"]["elasticsearch"]
es_client = Elasticsearch(es_config["host"], http_compress=True, request_timeout=5, max_retries=10)

actions = []
for event_time, ip_address, user_id, client_id, kind in stats:
    application = applications.get(client_id)
    user = users.get(user_id)
    if application and user:
        actions.append(
            {
                "_source": {
                    "ip_address": ip_address,
                    "application": client_id,
                    "event": kind.lower(),
                    "user": user_id,
                    "@timestamp": parse_keycloak_dt(event_time),
                    "name": "inclusion_connect.auth",
                    "levelname": "INFO",
                }
            }
        )
print(f"Sending {len(actions)} logs")
bulk(client=es_client, actions=actions, index=es_config["index_name"], stats_only=True)
print("Done!")
