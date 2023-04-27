from django import forms
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError
from django.forms import HiddenInput
from django.templatetags.static import static
from django.urls import reverse
from django.utils.html import format_html

from inclusion_connect.users.models import User


EMAIL_FIELDS_WIDGET_ATTRS = {"type": "email", "placeholder": "nom@domaine.fr", "autocomplete": "email"}
PASSWORD_PLACEHOLDER = "**********"


class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse e-mail",
        widget=forms.TextInput(attrs=EMAIL_FIELDS_WIDGET_ATTRS),
    )
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "placeholder": PASSWORD_PLACEHOLDER}),
    )

    def __init__(self, request=None, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if email is not None and password:
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
                raise ValidationError(
                    (
                        "Adresse e-mail ou mot de passe invalide."
                        "\nSi vous n’avez pas encore créé votre compte Inclusion Connect, "
                        "rendez-vous en bas de page et cliquez sur créer mon compte."
                    ),
                    code="invalid_login",
                )
        return self.cleaned_data

    def get_user(self):
        return self.user_cache


class RegistrationForm(auth_forms.UserCreationForm):
    terms_accepted = forms.BooleanField(
        label=format_html(
            "J'ai lu et j'accepte les <a href='{}' target='_blank'>conditions générales d’utilisation du service</a> "
            "ainsi que la <a href='{}' target='_blank'>politique de confidentialité</a>.",
            static("terms/CGU_20230302.pdf"),
            static("terms/Politique de confidentialité_20230302.pdf"),
        )
    )

    class Meta:
        model = User
        fields = ("last_name", "first_name", "email")

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.filter(email=email).exists():
            raise ValidationError(
                format_html(
                    'Un compte avec cette adresse e-mail existe déjà, <a href="{}">Se connecter</a> ?',
                    reverse("accounts:login"),
                )
            )
        return email

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["password1", "password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER

        self.fields["email"].widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS

    def save(self, commit=True):
        self.instance.terms_accepted_at = self.instance.date_joined
        return super().save(commit)


class AccountActivationForm(RegistrationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in ["first_name", "last_name", "email"]:
            self.fields[field].widget = HiddenInput()


class PasswordResetForm(auth_forms.PasswordResetForm):
    # email subject in templates/registration/password_reset_subject.txt
    # email body in templateS/registration/password_reset_email.html

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].label = "Adresse e-mail"
        self.fields["email"].widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS


class SetPasswordForm(auth_forms.SetPasswordForm):
    # email subject in templates/registration/password_reset_subject.txt
    # email body in templateS/registration/password_reset_email.html

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["new_password1", "new_password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER
