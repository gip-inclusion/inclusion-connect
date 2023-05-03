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

    # Denormalized verified email. See EmailAddress.
    email = CIEmailField(verbose_name="adresse e-mail", blank=True, db_index=True)
    password = models.CharField("password", max_length=256)  # allow compat with old keycloak passwords
    terms_accepted_at = models.DateTimeField("date de validation des CGUs", blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                "email",
                name="unique_email_if_not_empty",
                condition=~models.Q(email=""),
                violation_error_message="Cet email est déjà associé à un autre utilisateur.",
            ),
        ]

    def __str__(self):
        text = self.get_full_name()
        if self.email:
            text += f" — {self.email}"
        return text

    @property
    def id(self):
        # Required by some third party libraries that use user.id (django-oauth-toolkit)
        return self.pk

    @property
    def must_accept_terms(self):
        return self.terms_accepted_at is None or self.terms_accepted_at < settings.NEW_TERMS_DATE


class EmailAddress(models.Model):
    """
    Allows validating email adresses uniqueness regardless of their verified state.

    Subscription: email address not verified, user.email is None
    Email validation: email address verified, user.email == email

    Upon email change: 2 email addresses, user.email == old_email:
        - the old email address is verified
        - the new email address is not verified
    When the new email is verified, the old email address is deleted, user.email == new_email
    """

    email = CIEmailField("adresse e-mail", primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="email_addresses")
    created_at = models.DateTimeField(editable=False, default=timezone.now, verbose_name="date de création")
    verified_at = models.DateTimeField(null=True, blank=True, verbose_name="date de vérification")

    class Meta:
        verbose_name = "addresse e-mail"
        verbose_name_plural = "addresses e-mail"

    def __str__(self):
        verified = f"verified since {self.verified_at}" if self.verified_at else "not verified"
        return f"{self.email}: {verified}"

    def save(self, *args, **kwargs):
        if self.verified_at:
            self.user.email = self.email
            self.user.save()
        super().save(*args, **kwargs)

    def verify(self, verified_at=None):
        self.verified_at = verified_at or timezone.now()
        self.save(update_fields=["verified_at"])
        # Free unused email addresses for other users.
        type(self).objects.filter(user_id=self.user_id).exclude(pk=self.pk).delete()


class UserApplicationLink(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="utilisateur",
        related_name="linked_applications",
        on_delete=models.CASCADE,
    )
    application = models.ForeignKey(
        settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
        verbose_name="application",
        related_name="linked_users",
        on_delete=models.CASCADE,
    )
    last_login = models.DateTimeField("dernière connexion", default=timezone.now)
