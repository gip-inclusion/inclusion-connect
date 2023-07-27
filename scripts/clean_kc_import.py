#!/usr/bin/env python3

import os
import pathlib
import sys


sys.path.append(str(pathlib.Path(__file__).parent.parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "inclusion_connect.settings.dev")
import django


django.setup()

from django.db import connection


with connection.cursor() as cursor:
    cursor.execute(
        """
        TRUNCATE
            keycloak_compat_jwthashsecret,
            oidc_overrides_application,
            stats_stats,
            users_emailaddress,
            users_userapplicationlink
        CASCADE
        """
    )
    cursor.execute("DELETE FROM users_user WHERE is_staff IS NOT True")
    for sequence in [
        "oidc_overrides_application_id_seq",
        "stats_stats_id_seq",
        "users_emailaddress_id_seq",
        "users_userapplicationlink_id_seq",
        "users_user_groups_id_seq",
        "users_user_user_permissions_id_seq",
        "django_admin_log_id_seq",
        "oauth2_provider_accesstoken_id_seq",
        "oauth2_provider_grant_id_seq",
        "oauth2_provider_refreshtoken_id_seq",
        "oauth2_provider_idtoken_id_seq",
    ]:
        cursor.execute(f"ALTER SEQUENCE {sequence} RESTART WITH 1")
