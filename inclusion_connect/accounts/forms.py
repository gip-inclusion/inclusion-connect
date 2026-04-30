from django import forms
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError


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
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache:
                self.log["user"] = self.user_cache.email
            else:
                self.log["email"] = email
                raise ValidationError(
                    ("Adresse e-mail ou mot de passe invalide."),
                    code="invalid_login",
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

    def save(self, *args, request=None, **kwargs):
        super().save(*args, request=request, **kwargs)
        email = self.cleaned_data["email"]
        if next_url := request.session.get("next_url"):
            users = list(self.get_users(email))
            if users:
                [user] = users
                user.save_next_redirect_uri(next_url)


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
