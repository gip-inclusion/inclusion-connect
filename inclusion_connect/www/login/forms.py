from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError


class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse e-mail",
        widget=forms.TextInput(attrs={"type": "email", "placeholder": "nom@domaine.fr", "autocomplete": "email"}),
    )
    password = forms.CharField(
        label="Mot de passe",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "placeholder": "**********"}),
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
