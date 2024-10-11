# Generated by Django 4.1.7 on 2023-04-17 15:18

import uuid

import citext
import django.contrib.auth.models
import django.contrib.auth.validators
import django.contrib.postgres.fields.citext
import django.contrib.postgres.indexes
import django.utils.timezone
from django.contrib.postgres.operations import BtreeGistExtension, CITextExtension, TrigramExtension, UnaccentExtension
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        # Install PostgreSQL extensions
        # The 'asp' app has been chosen as entry point because it's central
        # dependency on the application and its migrations are processed early in the chain.
        BtreeGistExtension(),
        CITextExtension(),
        TrigramExtension(),
        UnaccentExtension(),
        migrations.RunSQL("DROP TEXT SEARCH CONFIGURATION IF EXISTS french_unaccent"),
        migrations.RunSQL("CREATE TEXT SEARCH CONFIGURATION french_unaccent (COPY = french)"),
        migrations.RunSQL(
            """
            ALTER TEXT SEARCH CONFIGURATION french_unaccent
                ALTER MAPPING FOR hword, hword_part, word
                    WITH unaccent, french_stem
            """
        ),
        migrations.CreateModel(
            name="User",
            fields=[
                ("last_login", models.DateTimeField(blank=True, null=True, verbose_name="last login")),
                (
                    "is_superuser",
                    models.BooleanField(
                        default=False,
                        help_text="Designates that this user has all permissions without explicitly assigning them.",
                        verbose_name="superuser status",
                    ),
                ),
                ("first_name", models.CharField(blank=True, max_length=150, verbose_name="first name")),
                ("last_name", models.CharField(blank=True, max_length=150, verbose_name="last name")),
                (
                    "is_staff",
                    models.BooleanField(
                        default=False,
                        help_text="Designates whether the user can log into this admin site.",
                        verbose_name="staff status",
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="Designates whether this user should be treated as active. "
                        "Unselect this instead of deleting accounts.",
                        verbose_name="active",
                    ),
                ),
                ("date_joined", models.DateTimeField(default=django.utils.timezone.now, verbose_name="date joined")),
                (
                    "username",
                    models.UUIDField(
                        default=uuid.uuid4, editable=False, primary_key=True, serialize=False, unique=True
                    ),
                ),
                (
                    "email",
                    citext.CIEmailField(db_index=True, max_length=254, unique=True, verbose_name="adresse e-mail"),
                ),
                ("password", models.CharField(max_length=256, verbose_name="mot de passe")),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        help_text="The groups this user belongs to. A user will get all permissions "
                        "granted to each of their groups.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.group",
                        verbose_name="groups",
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        help_text="Specific permissions for this user.",
                        related_name="user_set",
                        related_query_name="user",
                        to="auth.permission",
                        verbose_name="user permissions",
                    ),
                ),
            ],
            options={
                "verbose_name": "utilisateur",
                "abstract": False,
            },
            managers=[
                ("objects", django.contrib.auth.models.UserManager()),
            ],
        ),
    ]
