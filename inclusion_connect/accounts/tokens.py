from django.core.signing import TimestampSigner
from django.utils.http import urlsafe_base64_encode


def email_verification_token(email: str):
    encoded_email = urlsafe_base64_encode(email.encode())
    return TimestampSigner().sign(encoded_email)
