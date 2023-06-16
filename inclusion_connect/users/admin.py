import copy

from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin, forms as auth_forms, password_validation
from django.core.exceptions import ValidationError
from django.db.models import F, Prefetch
from django.forms.formsets import DELETION_FIELD_NAME

from .models import EmailAddress, User, UserApplicationLink


def is_email_verified(form):
    return not form.cleaned_data.get(DELETION_FIELD_NAME) and form.cleaned_data.get("verified_at")


class EmailAddressInlineFormSet(forms.BaseInlineFormSet):
    def clean(self):
        super().clean()
        verified_addresses = 0
        unverified_addresses = 0
        for form in self.forms:
            if is_email_verified(form):
                verified_addresses += 1
            elif not self._should_delete_form(form):
                unverified_addresses += 1
        if verified_addresses >= 2 or unverified_addresses >= 2:
            non = "non " if unverified_addresses >= 2 else ""
            raise ValidationError(f"L’utilisateur ne peut avoir qu’une seule adresse e-mail {non}vérifiée.")
        if verified_addresses + unverified_addresses == 0:
            raise ValidationError("L’utilisateur doit avoir au moins une adresse email.")

    def save(self, commit=True):
        for i, form in enumerate(self.forms):
            newly_verified = not form.initial.get("verified_at") and is_email_verified(form)
            if newly_verified:
                verified_email_address = form.instance
                try:
                    self.deleted_objects = [self.forms[1 - i].instance]
                except IndexError:
                    self.deleted_objects = []
                if verified_email_address.pk is None:
                    self.new_objects = [verified_email_address]
                    self.changed_objects = []
                else:
                    self.new_objects = []
                    self.changed_objects = [(verified_email_address, form.changed_data)]
                verified_email_address.verify(form.cleaned_data["verified_at"])
                return [verified_email_address]
        return super().save(commit=commit)


class EmailAddressInline(admin.TabularInline):
    extra = 0
    min_num = 1  # Must have an email address.
    max_num = 2  # 1 verified and 1 not verified.
    model = EmailAddress
    readonly_fields = ["created_at"]
    formset = EmailAddressInlineFormSet
    fields = ["email", "verified_at", "created_at"]
    ordering = [F("verified_at").desc(nulls_last=True), "email"]


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


class UserChangeForm(auth_forms.UserChangeForm):
    password = None
    must_reset_password = forms.Field(
        label="Mot de passe",
        disabled=True,
        required=False,
        widget=TemporaryPasswordWidget,
    )


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    model = User
    form = UserChangeForm
    readonly_fields = ["username", "email", "terms_accepted_at", "date_joined", "last_login"]
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

    @admin.display(description="Email à valider")
    def email_to_validate(self, obj):
        email_to_validate = obj.email_to_validate
        if email_to_validate:
            return email_to_validate[0].email
        else:
            return None

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        [email_address_formset, user_application_link_formset] = formsets
        if form.instance.email and not any(is_email_verified(fs) for fs in email_address_formset):
            form.instance.email = ""
            form.instance.save(update_fields=["email"])

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        is_change_form = obj is not None
        if is_change_form:
            assert fieldsets[0] == (None, {"fields": ("username", "password")})
            fieldsets = list(copy.deepcopy(fieldsets))
            fieldsets[0][1]["fields"] = ("username", "must_reset_password")

            fieldsets.append(("CGU", {"fields": ["terms_accepted_at"]}))

            assert fieldsets[2][0] == "Permissions"
            if request.user.is_superuser:
                if obj and not obj.is_staff:
                    # Hide space-consuming widgets for groups and user_permissions.
                    fieldsets[2] = ("Permissions", {"fields": ["is_active", "is_staff", "is_superuser"]})
            else:
                del fieldsets[2]
        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        rof = super().get_readonly_fields(request, obj)
        if not request.user.is_superuser:
            rof = [*rof, "is_staff", "is_superuser", "groups", "user_permissions"]
        return rof

    def get_queryset(self, request):
        return (
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
