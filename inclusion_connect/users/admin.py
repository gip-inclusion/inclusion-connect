import copy

from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin, forms as auth_forms, password_validation
from django.core.exceptions import ValidationError
from django.db.models import F, Prefetch
from django.forms.formsets import DELETION_FIELD_NAME
from django.utils.safestring import mark_safe

from .models import EmailAddress, User, UserApplicationLink


def is_email_verified(form):
    return not form.cleaned_data.get(DELETION_FIELD_NAME) and form.cleaned_data.get("verified_at")


class EmailAddressInline(admin.TabularInline):
    extra = 0
    model = EmailAddress
    readonly_fields = ["email", "verified_at", "created_at"]
    ordering = [F("verified_at").desc(nulls_last=True), "email"]

    can_delete = False

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj):
        return False


class AdminPasswordChangeForm(forms.Form):
    """
    A form used to change the password of a user in the admin interface.
    """

    required_css_class = "required"
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.TextInput(attrs={"autocomplete": "new-password", "autofocus": True}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        password = self.cleaned_data.get("password")
        password_validation.validate_password(password, self.user)
        return password

    def save(self, commit=True):
        password = self.cleaned_data["password"]
        self.user.set_password(password)
        self.user.must_reset_password = True
        if commit:
            self.user.save()
        return self.user

    @property
    def changed_data(self):
        data = super().changed_data
        for name in self.fields:
            if name not in data:
                return []
        return ["password"]


class UserApplicationLinkInline(admin.TabularInline):
    model = UserApplicationLink
    extra = 0
    can_delete = False

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj):
        return False


class TemporaryPasswordWidget(forms.Widget):
    template_name = "admin/widgets/temporary_password.html"


class ConfirmEmailWidget(forms.TextInput):
    template_name = "admin/widgets/confirm_email.html"

    def __init__(self, attrs=None, unverified_email=None):
        super().__init__(attrs)
        self.unverified_email = unverified_email

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        return context | {"unverified_email": self.unverified_email}


class UserChangeForm(auth_forms.UserChangeForm):
    password = None
    must_reset_password = forms.Field(
        label="Mot de passe",
        disabled=True,
        required=False,
        widget=TemporaryPasswordWidget,
    )
    confirm_email = forms.BooleanField(
        label=mark_safe('<img src="/static/admin/img/icon-alert.svg" alt="True"> Confirmer l’e-mail'),
        disabled=True,
        required=False,
        widget=forms.HiddenInput(),
    )

    def __init__(self, *args, instance, **kwargs):
        super().__init__(*args, instance=instance, **kwargs)
        email = self.fields["email"]
        email.label = "Adresse e-mail vérifiée"

        email_to_validate = instance.email_to_validate
        if email_to_validate:
            confirm_email = self.fields["confirm_email"]
            unverified_email = email_to_validate[0].email
            confirm_email.disabled = False
            confirm_email.widget = ConfirmEmailWidget(unverified_email=unverified_email)

    def clean_email(self):
        new_email = self.cleaned_data.get("email")
        if self.initial["email"] != new_email and new_email == "":
            raise ValidationError("Vous ne pouvez pas supprimer l'adresse e-mail de l'utilsateur.")
        return self.cleaned_data.get("email")

    def clean(self):
        super().clean()
        new_email = self.cleaned_data.get("email")
        if (
            self.initial["email"] != new_email
            and self.cleaned_data["confirm_email"]
            and self.instance.email_to_validate[0].email != new_email
        ):
            raise ValidationError("Vous ne pouvez pas à la fois modifier l'email validé, et confirmer un email")

    def save(self, commit=True):
        new_email = self.cleaned_data["email"]
        if self.cleaned_data["confirm_email"]:
            self.instance.email_to_validate[0].verify()
            self.instance.email = self.instance.email_to_validate[0].email
        elif self.initial["email"] != new_email:
            email_address = EmailAddress(user=self.instance, email=new_email)
            email_address.verify()
        return super().save(commit=commit)


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    model = User
    form = UserChangeForm
    readonly_fields = ["username", "terms_accepted_at", "date_joined", "last_login"]
    list_filter = auth_admin.UserAdmin.list_filter + ("must_reset_password",)
    inlines = [EmailAddressInline, UserApplicationLinkInline]
    change_password_form = AdminPasswordChangeForm
    search_fields = auth_admin.UserAdmin.search_fields + ("email_addresses__email",)
    list_display = (
        "username",
        "email",
        "email_to_validate",
        "first_name",
        "last_name",
        "is_staff",
    )
    filter_horizontal = ("support_for",)

    @admin.display(description="Email à valider")
    def email_to_validate(self, obj):
        email_to_validate = obj.email_to_validate
        if email_to_validate:
            return email_to_validate[0].email
        else:
            return None

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        is_change_form = obj is not None
        if is_change_form:
            assert fieldsets[0] == (None, {"fields": ("username", "password")})
            assert fieldsets[1] == ("Informations personnelles", {"fields": ("first_name", "last_name", "email")})
            fieldsets = list(copy.deepcopy(fieldsets))
            fieldsets[0][1]["fields"] = ("username", "must_reset_password")
            fieldsets[1][1]["fields"] += ("confirm_email",)

            fieldsets.append(("CGU", {"fields": ["terms_accepted_at"]}))

            assert fieldsets[2][0] == "Permissions"
            if request.user.is_superuser:
                if obj and not obj.is_staff:
                    # Hide space-consuming widgets for groups and user_permissions.
                    fieldsets[2] = ("Permissions", {"fields": ["is_active", "is_staff", "is_superuser"]})
                else:
                    fieldsets[2][1]["fields"] += ("support_for",)
            else:
                del fieldsets[2]
        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        rof = super().get_readonly_fields(request, obj)
        if not request.user.is_superuser:
            rof = [*rof, "is_staff", "is_superuser", "groups", "user_permissions"]
        return rof

    def get_queryset(self, request):
        queryset = (
            super()
            .get_queryset(request)
            .prefetch_related(
                Prefetch(
                    "email_addresses",
                    queryset=EmailAddress.objects.filter(verified_at=None),
                    to_attr="email_to_validate",
                )
            )
        )

        if not request.user.is_superuser:
            queryset = queryset.filter(linked_applications__application__in=request.user.support_for.all())

        return queryset
