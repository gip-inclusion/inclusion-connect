import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import CIEmailField
from django.db import models
from django.utils import timezone


class User(AbstractUser):
    """
    Custom user model.

    Default fields are listed here:
    https://github.com/django/django/blob/f3901b5899d746dc5b754115d94ce9a045b4db0a/django/contrib/auth/models.py#L321

    Auth is managed with django-oauth-tooklit (for OIDC users)
    """

    # Change default id to uuid4 (used as sub in OIDC protocol) and use as pk
    username = models.UUIDField(unique=True, default=uuid.uuid4, editable=False, primary_key=True)

    email = CIEmailField(
        "Adresse e-mail",
        db_index=True,
        unique=True,
    )
    password = models.CharField("password", max_length=256)  # allow compat with old keycloak passwords
    terms_accepted_at = models.DateTimeField("Date de validation des CGUs", blank=True, null=True)

    def __str__(self):
        return f"{self.get_full_name()} — {self.email}"

    @property
    def id(self):
        # Required by some third party libraries that use user.id (django-oauth-toolkit)
        return self.pk


class UserApplicationLink(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="Utilisateur",
        related_name="linked_applications",
        on_delete=models.CASCADE,
    )
    application = models.ForeignKey(
        settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
        verbose_name="Application",
        related_name="linked_users",
        on_delete=models.CASCADE,
    )
    last_login = models.DateTimeField("Dernière connexion", default=timezone.now)
