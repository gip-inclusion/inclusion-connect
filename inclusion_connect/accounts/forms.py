from django import forms
from django.conf import settings
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError

from inclusion_connect.accounts.emails import send_verification_email
from inclusion_connect.oidc_federation.enums import Federation
from inclusion_connect.users.models import EmailAddress, User


EMAIL_FIELDS_WIDGET_ATTRS = {"placeholder": "nom@domaine.fr", "autocomplete": "email"}
PASSWORD_PLACEHOLDER = "**********"
FRANCETRAVAIL_EMAIL_SUFFIX = ("@pole-emploi.fr", "@francetravail.fr")


class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse e-mail",
        widget=forms.EmailInput(attrs=EMAIL_FIELDS_WIDGET_ATTRS),
    )
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "placeholder": PASSWORD_PLACEHOLDER}),
    )

    def __init__(self, log, request, *args, **kwargs):
        self.log = log
        self.request = request
        super().__init__(*args, **kwargs)
        self.fields["email"].disabled = "email" in self.initial

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email is not None and password:
            # Don't allow federated users
            user = User.objects.filter(email=email).first()
            if (
                user
                and user.email.endswith(FRANCETRAVAIL_EMAIL_SUFFIX)
                and settings.PEAMA_ENABLED
                and not settings.PEAMA_STAGING
            ):
                error_message = (
                    "Votre compte est un compte agent France Travail. "
                    "Vous devez utiliser le bouton de connexion France Travail pour accéder au service."
                )
                self.log["user"] = user.pk
                raise forms.ValidationError(error_message)
            if user and user.federation:
                identity_provider = user.get_federation_display()
                error_message = (
                    f"Votre compte est relié à {identity_provider}. Merci de vous connecter avec ce service."
                )
                self.log["user"] = user.pk
                raise forms.ValidationError(error_message)

            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache:
                self.log["user"] = self.user_cache.pk
            else:
                self.log["email"] = email
                try:
                    email_address = EmailAddress.objects.get(email=email, verified_at=None)
                except EmailAddress.DoesNotExist as e:
                    raise ValidationError(
                        (
                            "Adresse e-mail ou mot de passe invalide."
                            "\nSi vous n’avez pas encore créé votre compte Inclusion Connect, "
                            "rendez-vous en bas de page et cliquez sur créer mon compte."
                        ),
                        code="invalid_login",
                    ) from e
                else:
                    send_verification_email(self.request, email_address)
                    raise ValidationError(
                        "Un compte inactif avec cette adresse e-mail existe déjà, "
                        "l’email de vérification vient d’être envoyé à nouveau.",
                        code="unverified_email",
                    )
        return self.cleaned_data

    def get_user(self):
        return self.user_cache


class PasswordResetForm(auth_forms.PasswordResetForm):
    def __init__(self, *args, initial, **kwargs):
        super().__init__(*args, initial=initial, **kwargs)
        email_field = self.fields["email"]
        email_field.label = "Adresse e-mail"
        email_field.widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS.copy()
        email_field.disabled = "email" in initial

    def get_users(self, email, is_federated=False):
        users = super().get_users(email)
        return [user for user in users if bool(user.federation) == is_federated]

    def save(self, *args, request=None, from_email=None, **kwargs):
        super().save(*args, request=request, **kwargs)
        email = self.cleaned_data["email"]
        if next_url := request.session.get("next_url"):
            users = list(self.get_users(email))
            if users:
                [user] = users
                user.save_next_redirect_uri(next_url)
        for user in self.get_users(email, is_federated=True):
            self.send_mail(
                "registration/password_reset_subject.txt",
                "registration/password_reset_body_federation.txt",
                {"federation": Federation(user.federation).label},
                from_email,
                user.email,
                html_email_template_name="registration/password_reset_body_federation.html",
            )

    def clean_email(self):
        email = self.cleaned_data["email"]
        if email.endswith(FRANCETRAVAIL_EMAIL_SUFFIX) and settings.PEAMA_ENABLED and not settings.PEAMA_STAGING:
            suffix = email.rsplit("@", maxsplit=1)[-1]
            error_message = (
                f"Vous utilisez une adresse e-mail en @{suffix}. "
                "Vous devez utiliser le bouton de connexion France Travail pour accéder au service."
            )
            raise ValidationError(error_message)
        return email


class SetPasswordForm(auth_forms.SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["new_password1", "new_password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER

    def save(self, commit=True):
        self.user.password_is_temporary = False
        return super().save(commit)


class PasswordChangeForm(auth_forms.PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["old_password", "new_password1", "new_password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER
        self.fields["old_password"].label = "Mot de passe actuel"
