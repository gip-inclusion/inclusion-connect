import base64
import hashlib


# initial data
password = "RdaRfqP7Y89vy2"
# Keycloak stored credential
secret_data = {
    "value": "ZXVC08Hf4jBOoYzVoNWYjQijsMC2oc/OUa9LciiIJ/1XHPF/qPiY1DqwLLDN2hYFmf/1kApkveD8/Pr7GVqjgw==",
    "salt": "Td6XuopYK6JNfUnIlqYMOQ==",
    "additionalParameters": {},
}
credentials_data = {
    "hashIterations": 27500,
    "algorithm": "pbkdf2-sha256",
    "additionalParameters": {},
}

kc_hash = secret_data["value"]
kc_salt = secret_data["salt"]
iterations = credentials_data["hashIterations"]
algorithm = "pbkdf2-sha256"

django_stored_password = f"{algorithm}${iterations}${kc_salt}${kc_hash}"

base64.b64encode(
    hashlib.pbkdf2_hmac(
        hashlib.sha256().name,
        password.encode(),
        base64.decodebytes(kc_salt.encode()),
        iterations,
        64,
    )
).decode("ascii").strip() == kc_hash


# penser à ré-hasher les mot de passe à la volée
# pour pouvoir virer le code de compatibilité

# compat navigateur : http 307
