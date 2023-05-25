import copy

from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin, forms as auth_forms
from django.core.exceptions import ValidationError
from django.db.models import F
from django.forms.formsets import DELETION_FIELD_NAME

from .models import EmailAddress, User


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


class AdminPasswordChange(auth_forms.AdminPasswordChangeForm):
    def save(self, commit=True):
        self.user.must_reset_password = True
        return super().save(commit)


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    model = User
    readonly_fields = ["username", "email", "terms_accepted_at"]
    list_filter = auth_admin.UserAdmin.list_filter + ("must_reset_password",)
    inlines = [EmailAddressInline]
    change_password_form = AdminPasswordChange
    search_fields = auth_admin.UserAdmin.search_fields + ("email_addresses__email",)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        [email_address_formset] = formsets
        if form.instance.email and not any(is_email_verified(fs) for fs in email_address_formset):
            form.instance.email = ""
            form.instance.save(update_fields=["email"])

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        assert fieldsets[0] == (None, {"fields": ("username", "password")})
        new_fieldsets = list(copy.deepcopy(fieldsets))
        new_fieldsets[0][1]["fields"] += ("must_reset_password",)
        new_fieldsets.append(("CGU", {"fields": ["terms_accepted_at"]}))
        return new_fieldsets
