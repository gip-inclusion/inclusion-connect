# Generated by Django 4.1.8 on 2023-04-27 11:46

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.OAUTH2_PROVIDER_APPLICATION_MODEL),
        ("users", "0002_user_terms_accepted_at"),
    ]

    operations = [
        migrations.CreateModel(
            name="UserApplicationLink",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "last_login",
                    models.DateTimeField(default=django.utils.timezone.now, verbose_name="dernière connexion"),
                ),
                (
                    "application",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="linked_users",
                        to=settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
                        verbose_name="application",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="linked_applications",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="utilisateur",
                    ),
                ),
            ],
            options={
                "verbose_name": "service utilisé",
                "verbose_name_plural": "services utilisés",
            },
        ),
    ]
