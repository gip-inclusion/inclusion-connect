from django.db import models


class Federation(models.TextChoices):
    PEAMA = "peama", "France Travail"
