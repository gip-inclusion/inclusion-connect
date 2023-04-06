import uuid

from django.contrib.auth.models import AbstractUser
from django.contrib.postgres.fields import CIEmailField
from django.db import models


class User(AbstractUser):
    """
    Custom user model.

    Default fields are listed here:
    https://github.com/django/django/blob/f3901b5899d746dc5b754115d94ce9a045b4db0a/django/contrib/auth/models.py#L321

    Auth is managed with django-oauth-tooklit (for OIDC users)
    """

    # Change default id to uuid4 (used as sub in OIDC protocol)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = CIEmailField(
        "Adresse e-mail",
        blank=True,
        db_index=True,
        unique=True,
    )
    password = models.CharField("password", max_length=256)  # allow compat with old keycloak passwords

    def __str__(self):
        return f"{self.get_full_name()} — {self.email}"

    # habdle verified email with django-allauth ?

    @classmethod
    def email_already_exists(cls, email, exclude_pk=None):
        """
        RFC 5321 Part 2.4 states that only the domain portion of an email
        is case-insensitive. Consider toto@toto.com and TOTO@toto.com as
        the same email.
        """
        queryset = cls.objects.filter(email__iexact=email)
        if exclude_pk:
            queryset = queryset.exclude(pk=exclude_pk)
        return queryset.exists()
