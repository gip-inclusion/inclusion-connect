import datetime
import uuid

from citext import CIEmailField
from django.conf import settings
from django.contrib.auth.models import AbstractUser
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

    email = CIEmailField(verbose_name="adresse e-mail", blank=True, db_index=True)
    password = models.CharField("mot de passe", max_length=256)  # allow compat with old keycloak passwords

    # Triggers for required actions
    password_is_temporary = models.BooleanField("mot de passe temporaire", default=False)
    password_is_too_weak = models.BooleanField("mot de passe trop faible", default=False)

    # Allow to redirect user correctly even when using a link from another browser (without session data)
    next_redirect_uri = models.TextField(blank=True, null=True)
    next_redirect_uri_stored_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        verbose_name = "utilisateur"
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

    def save_next_redirect_uri(self, next_redirect_uri):
        self.next_redirect_uri = next_redirect_uri
        self.next_redirect_uri_stored_at = timezone.now()
        self.save(update_fields=["next_redirect_uri", "next_redirect_uri_stored_at"])

    def pop_next_redirect_uri(self):
        next_url = self.next_redirect_uri
        if next_url and self.next_redirect_uri_stored_at < timezone.now() - datetime.timedelta(days=1):
            next_url = None
        self.next_redirect_uri = None
        self.next_redirect_uri_stored_at = None
        self.save(update_fields=["next_redirect_uri", "next_redirect_uri_stored_at"])
        return next_url


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

    class Meta:
        verbose_name = "service utilisé"
        verbose_name_plural = "services utilisés"
        unique_together = ("user", "application")

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.application}"
