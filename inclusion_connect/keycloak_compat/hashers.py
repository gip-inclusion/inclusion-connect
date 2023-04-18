import base64

from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.utils.crypto import pbkdf2


class KeycloakPasswordHasher(PBKDF2PasswordHasher):
    algorithm = "keycloak-pbkdf2-sha256"
    iterations = 27500
    dklen = 64

    def encode(self, password, salt, iterations=None):
        self._check_encode_args(password, salt)
        iterations = iterations or self.iterations
        hash = pbkdf2(
            password,
            base64.decodebytes(salt.encode()),  # Keycloak salt is not in the same format
            iterations,
            dklen=self.dklen,
            digest=self.digest,
        )
        hash = base64.b64encode(hash).decode("ascii").strip()
        return "%s$%d$%s$%s" % (self.algorithm, iterations, salt, hash)
