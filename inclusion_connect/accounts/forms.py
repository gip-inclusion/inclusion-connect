from django import forms
from django.conf import settings
from django.contrib.auth import authenticate, forms as auth_forms
from django.core.exceptions import ValidationError
from django_otp import match_token


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

        if settings.DEMO_MODE:
            # Remove password
            self.fields["password"].widget = forms.HiddenInput()
            self.fields["password"].required = False
            # Add ffirst_name and last_name

    def clean(self):
        email = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        if settings.DEMO_MODE:
            self.user_cache = authenticate(
                self.request,
                email=email,
                password=password,
            )
            if self.user_cache is None:
                raise ValidationError(
                    ("Adresse e-mail invalide."),
                    code="invalid_login",
                )

        if email is not None and password:
            self.user_cache = authenticate(self.request, email=email, password=password)
            if self.user_cache is None:
                raise ValidationError(
                    ("Adresse e-mail ou mot de passe invalide."),
                    code="invalid_login",
                )
        return self.cleaned_data

    def get_user(self):
        return self.user_cache


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


class ConfirmTOTPDeviceForm(forms.Form):
    name = forms.CharField(label="Nom de l'appareil")
    otp_token = forms.CharField()

    otp_token.widget.attrs.update({"max_length": 6, "autocomplete": "one-time-code"})

    def __init__(self, *args, device, **kwargs):
        super().__init__(*args, **kwargs)
        self.device = device

    def clean(self):
        cleaned_data = super().clean()

        otp_token = cleaned_data["otp_token"]
        if self.device.verify_token(otp_token) is False:
            self.add_error("otp_token", "Mauvais code OTP")

        return cleaned_data


class VerifyOTPForm(forms.Form):
    otp_token = forms.CharField(required=True)

    otp_token.widget.attrs.update(
        {
            "max_length": 6,
            "autocomplete": "one-time-code",
            "autofocus": True,
        }
    )

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user

    def clean_otp_token(self):
        otp_token = self.cleaned_data.get("otp_token")

        device = match_token(self.user, otp_token)
        if device is None:
            raise ValidationError("code invalide")
        self.user.otp_device = device

        return otp_token
