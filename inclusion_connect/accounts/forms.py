from django import forms
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError

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
    class Meta:
        model = User
        fields = ("last_name", "first_name", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in ["password1", "password2"]:
            self.fields[key].widget.attrs["placeholder"] = PASSWORD_PLACEHOLDER

        self.fields["email"].widget.attrs = EMAIL_FIELDS_WIDGET_ATTRS


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
