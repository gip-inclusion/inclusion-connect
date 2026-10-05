from django import forms
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError


EMAIL_FIELDS_WIDGET_ATTRS = {"placeholder": "nom@domaine.fr", "autocomplete": "email"}
PASSWORD_PLACEHOLDER = "**********"


class LoginForm(forms.Form):
    email = forms.EmailField(
        label="Adresse e-mail",
        widget=forms.EmailInput(attrs=EMAIL_FIELDS_WIDGET_ATTRS),
    )
    first_name = forms.CharField(
        label="Prénom",
        required=False,
    )
    last_name = forms.CharField(
        label="Nom",
        required=False,
    )

    def __init__(self, request, *args, **kwargs):
        self.request = request
        super().__init__(*args, **kwargs)
        self.fields["email"].disabled = "email" in self.initial

    def clean(self):
        email = self.cleaned_data.get("email")

        self.user_cache = authenticate(
            self.request,
            email=email,
            password="",
            first_name=self.cleaned_data["first_name"],
            last_name=self.cleaned_data["last_name"],
        )
        if self.user_cache is None:
            raise ValidationError(
                ("Adresse e-mail invalide."),
                code="invalid_login",
            )

        return self.cleaned_data

    def get_user(self):
        return self.user_cache
