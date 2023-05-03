from django.db import models


class JWTHashSecret(models.Model):
    realm_id = models.TextField(primary_key=True)
    # urlsafe_base64_encoded.
    secret = models.TextField()
