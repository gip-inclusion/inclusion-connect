from django.core.mail import EmailMultiAlternatives
from django.db import transaction
from django.http import HttpRequest
from django.template import loader
from django.urls import reverse
from django.utils import http

from inclusion_connect.accounts import tokens
from inclusion_connect.users.models import EmailAddress


def send_verification_email(request: HttpRequest, email_address: EmailAddress):
    uidb64 = http.urlsafe_base64_encode(str(email_address.user_id).encode())
    context = {
        "token_url": request.build_absolute_uri(
            reverse(
                "accounts:confirm-email-token",
                kwargs={
                    "uidb64": uidb64,
                    "token": tokens.email_verification_token(email_address.email),
                },
            )
        )
    }
    subject = loader.render_to_string("registration/email_verification_subject.txt", context).strip()
    html_email = loader.render_to_string("registration/email_verification_body.html", context)
    body = loader.render_to_string("registration/email_verification_body.txt", context)
    email_message = EmailMultiAlternatives(subject, body, to=[email_address.email])
    email_message.attach_alternative(html_email, "text/html")
    transaction.on_commit(email_message.send)
