from django import forms
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError
from django.forms import HiddenInput
from django.templatetags.static import static
from django.urls import reverse
from django.utils.html import format_html

from inclusion_connect.accounts.emails import send_verification_email
from inclusion_connect.users.models import EmailAddress, User


EMAIL_FIELDS_WIDGET_ATTRS = {"placeholder": "nom@domaine.fr", "autocomplete": "email"}
PASSWORD_PLACEHOLDER = "**********"


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

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)
        self.fields["email"].disabled = "email" in self.initial

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email is not None and password:
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
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
                        "l’email de vérification vient d’être envoyé à nouveau."
                    )
        return self.cleaned_data

    def get_user(self):
        return self.user_cache


def save_unverified_email(user, email):
    """Maintain a single unverified email address per user."""
    matched = EmailAddress.objects.filter(user=user, verified_at=None).update(email=email)
    if not matched:
        EmailAddress.objects.create(user=user, verified_at=None, email=email)


def verified_email_field():
    """
    A forms.EmailField for email addresses that need verification

    See :class:`inclusion_connect.models.EmailAddress` for an overview
    of the email verification process.
    """
    fields = forms.fields_for_model(EmailAddress, fields=["email"])
    email_field = fields["email"]
    email_field.widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS.copy()
    return email_field


class RegisterForm(auth_forms.UserCreationForm):
    terms_accepted = forms.BooleanField(
        label=format_html(
            "J'ai lu et j'accepte les <a href='{}' target='_blank'>conditions générales d’utilisation du service</a> "
            "ainsi que la <a href='{}' target='_blank'>politique de confidentialité</a>.",
            static("terms/CGU_20230302.pdf"),
            static("terms/Politique de confidentialité_20230512.pdf"),
        )
    )

    class Meta:
        model = User
        fields = ("last_name", "first_name")

    def __init__(self, *args, initial, request, **kwargs):
        self.request = request
        super().__init__(*args, initial=initial, **kwargs)
        for key in ["password1", "password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER
        # Do not record the email field on the User instance, the email must be validated first.
        email_field = verified_email_field()
        email_field.disabled = "email" in initial
        self.fields["email"] = email_field

    def clean_email(self):
        email = self.cleaned_data["email"]
        try:
            email_address = EmailAddress.objects.get(email=email)
        except EmailAddress.DoesNotExist:
            pass
        else:
            if email_address.verified_at:
                msg = format_html(
                    'Un compte avec cette adresse e-mail existe déjà, <a href="{}">se connecter</a> ?',
                    reverse("accounts:login"),
                )
            else:
                send_verification_email(self.request, email_address)
                msg = (
                    "Un compte inactif avec cette adresse e-mail existe déjà, "
                    "l’email de vérification vient d’être envoyé à nouveau."
                )
            raise ValidationError(msg)
        return email

    def save(self, commit=True):
        self.instance.terms_accepted_at = self.instance.date_joined
        user = super().save(commit=commit)
        save_unverified_email(user, self.cleaned_data["email"])
        return user


class ActivateAccountForm(RegisterForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in ["first_name", "last_name", "email"]:
            self.fields[field].widget = HiddenInput()

    def clean(self):
        super().clean()
        try:
            error = self.errors["email"]
        except KeyError:
            pass
        else:
            # The email field is hidden, users can’t see the error message on the field.
            self.add_error(None, error)


class PasswordResetForm(auth_forms.PasswordResetForm):
    def __init__(self, *args, initial, **kwargs):
        super().__init__(*args, initial=initial, **kwargs)
        email_field = self.fields["email"]
        email_field.label = "Adresse e-mail"
        email_field.widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS.copy()
        email_field.disabled = "email" in initial

    def save(self, *args, request=None, **kwargs):
        super().save(*args, request=request, **kwargs)
        email = self.cleaned_data["email"]
        if next_url := request.session.get("next_url"):
            [user] = self.get_users(email)
            user.save_next_redirect_uri(next_url)


class SetPasswordForm(auth_forms.SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["new_password1", "new_password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER

    def save(self, commit=True):
        self.user.must_reset_password = False
        return super().save(commit)


class EditUserInfoForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("last_name", "first_name")

    def __init__(self, *args, initial, instance, **kwargs):
        initial["email"] = instance.email
        super().__init__(*args, initial=initial, instance=instance, **kwargs)
        self.fields["email"] = verified_email_field()

    def clean_email(self):
        email = self.cleaned_data["email"]
        if EmailAddress.objects.exclude(user=self.instance).filter(email=email).exists():
            raise ValidationError("Un compte avec cette adresse e-mail existe déjà.")
        return email

    def save(self, commit=True):
        user = super().save(commit=commit)
        email = self.cleaned_data["email"]
        if email != user.email:
            save_unverified_email(user, email)
        return user


class PasswordChangeForm(auth_forms.PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["old_password", "new_password1", "new_password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER
