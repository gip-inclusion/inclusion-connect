from django.conf import settings
from django.db import models


class Actions(models.TextChoices):
    LOGIN = "login"
    REGISTER = "register"


class Stats(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="utilisateur",
        related_name="stats",
        on_delete=models.CASCADE,
    )
    application = models.ForeignKey(
        settings.OAUTH2_PROVIDER_APPLICATION_MODEL,
        verbose_name="application",
        related_name="stats",
        on_delete=models.CASCADE,
    )
    date = models.DateField("date de l'action")
    action = models.TextField("action", choices=Actions.choices)

    class Meta:
        unique_together = ["user", "application", "date", "action"]
