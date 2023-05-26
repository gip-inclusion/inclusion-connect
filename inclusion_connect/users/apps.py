from django.apps import AppConfig
from django.db import models


class AnalyticsConfig(AppConfig):
    name = "inclusion_connect.users"
    verbose_name = "Utilisateurs"

    def ready(self):
        super().ready()
        models.signals.post_migrate.connect(ensure_support_group, sender=self)


def ensure_support_group(*args, **kwargs):
    from django.contrib.auth.models import Group, Permission

    group, _created = Group.objects.get_or_create(name="support")
    group.permissions.set(
        Permission.objects.filter(
            codename__in=[
                "add_user",
                "change_user",
                "view_user",
                "add_emailaddress",
                "change_emailaddress",
                "delete_emailaddress",
                "view_emailaddress",
                "view_userapplicationlink",
            ]
        )
    )
