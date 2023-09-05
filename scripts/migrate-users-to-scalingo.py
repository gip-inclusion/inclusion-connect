#!/usr/bin/env python3
"""
Migrates users from CleverCloud to Scalingo.

When the disaster recovery plan (PRA) is enacted, the latest IC dump is
restored on Scalingo, and production traffic goes to Scalingo.
Users created after the latest dump are still linked to RP, so we can’t simply
lose the data. Instead, import the users from the CleverCloud database to the
Scalingo database.
"""
import functools
import os
import pathlib
import sys
from datetime import timedelta

import dj_database_url
import django
from django.conf import settings
from django.db import IntegrityError, connections, transaction
from django.db.models import Q
from django.utils import timezone


# Ignore rows before the cutoff to speed-up the migration.
@functools.cache
def cutoff():
    return timezone.now() - timedelta(days=62)  # At least 2 months.


def migrate_new_users():
    from inclusion_connect.users.models import User

    # Force evaluation, subqueries aren’t allowed across databases.
    scalingo_users_ids = list(User.objects.using("default").values_list("pk", flat=True))

    print("Migrating users…")
    users_to_create = (
        User.objects.using("clevercloud")
        .exclude(pk__in=scalingo_users_ids)
        .prefetch_related("email_addresses", "linked_applications", "stats")
    )
    users = 0
    email_addresses = 0
    linked_applications = 0
    stats = 0
    conflicts = []
    for user in users_to_create:
        try:
            user.save(using="default", force_insert=True)
        except IntegrityError:
            # User with the same email associated with a different PK.
            # Different RP may have a different handle on users with that e-mail,
            # require manual intervention.
            conflicts.append((user, User.objects.get(email=user.email).pk))
        else:
            users += 1
            for email_address in user.email_addresses.all():
                email_address.pk = None
                email_address.save(using="default")
                email_addresses += 1
            for linked_application in user.linked_applications.all():
                linked_application.pk = None
                linked_application.save(using="default")
                linked_applications += 1
            for stat in user.stats.all():
                stat.pk = None
                stat.save(using="default")
                stats += 1
    if conflicts:
        print("⚠️ Migration conflicts detected.")
        print(
            "Users on CleverCloud have a different ID on Scalingo, indicating duplicates.\n"
            "Their account has been linked to RP on both sides, manual action is required.\n"
            "Contact the RP so they update their user records from the CleverCloud ID to "
            "the Scalingo ID.\n"
        )
        print()
        print("CleverCloud ID,Scalingo ID,application links to reconcile (on Clever but not on Scalingo)")

        def applications(user):
            for link in user.linked_applications.all():
                yield link.application_id

        for cc_user, scalingo_user in conflicts:
            cc_apps = set(applications(cc_user))
            scalingo_apps = set(applications(scalingo_user))
            conflict_apps = ";".join(sorted(cc_apps - scalingo_apps))
            print(f"{cc_user.pk},{scalingo_user.pk},{conflict_apps}")
    print(
        f"Migrated {users} users, created {email_addresses} email addresses, "
        f"{stats} stats and {linked_applications} user application links."
    )


def migrate_email_addresses():
    from inclusion_connect.users.models import EmailAddress

    print("Migrating email addresses…")
    cc_email_addresses = {}
    for cc_email_address in EmailAddress.objects.using("clevercloud").exclude(verified_at=None):
        cc_email_addresses[cc_email_address.email] = cc_email_address
    scalingo_emails = set(EmailAddress.objects.values_list("email", flat=True))
    new_emails = set(cc_email_addresses) - scalingo_emails

    email_addresses_count = 0
    for email in new_emails:
        email_address = cc_email_addresses[email]
        if (
            email_address.verified_at
            and not EmailAddress.objects.filter(
                Q(created_at__gte=email_address.verified_at) | Q(verified_at__gte=email_address.verified_at),
                user_id=email_address.user_id,
            ).exists()
        ):
            EmailAddress.objects.filter(user_id=email_address.user_id).delete()
            email_address.pk = None
            email_address.save(using="default")
            email_addresses_count += 1
    print(f"Migrated {email_addresses_count} email addresses.")


def migrate_stats():
    from inclusion_connect.stats.models import Stats

    print("Migrating stats…")
    stats = 0
    for user_id, app_id, date, action in (
        Stats.objects.using("clevercloud")
        .filter(date__gte=cutoff().date())
        .values_list("user_id", "application_id", "date", "action")
    ):
        _, created = Stats.objects.get_or_create(user_id=user_id, application_id=app_id, date=date, action=action)
        if created:
            stats += 1
    print(f"Migrated {stats} stats.")


def migrate_user_app_links():
    from inclusion_connect.users.models import UserApplicationLink

    print("Migrating user application links…")
    links = 0
    for user_id, application_id, last_login in (
        UserApplicationLink.objects.using("clevercloud")
        .filter(last_login__gte=cutoff())
        .values_list("user_id", "application_id", "last_login")
    ):
        _, created = UserApplicationLink.objects.get_or_create(
            user_id=user_id,
            application_id=application_id,
            defaults={"last_login": last_login},
        )
        if created:
            links += 1
    print(f"Migrated {links} user application links.")


def main():
    clevercloud_db_uri = input("CleverCloud database direct URI? ").strip()
    settings.DATABASES["clevercloud"] = dj_database_url.parse(clevercloud_db_uri, ssl_require=True)
    connections.configure_settings(settings.DATABASES)

    with transaction.atomic():
        migrate_new_users()
        print()
        migrate_email_addresses()
        print()
        migrate_stats()
        print()
        migrate_user_app_links()


if __name__ == "__main__":
    sys.path.append(str(pathlib.Path(__file__).parent.parent))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "inclusion_connect.settings.base")

    django.setup()
    main()
