import copy

from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin, forms as auth_forms
from django.core.exceptions import ValidationError
from django.db.models import Exists, F, OuterRef, Q
from django.forms.formsets import DELETION_FIELD_NAME
from django.utils.text import smart_split, unescape_string_literal

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
            else:
                unverified_addresses += 1
        if verified_addresses >= 2 or unverified_addresses >= 2:
            non = "non " if unverified_addresses >= 2 else ""
            raise ValidationError(f"L’utilisateur ne peut avoir qu’une seule adresse e-mail {non}vérifiée.")

    def save(self, commit=True):
        instances = super().save(commit=True)
        for form in self.forms:
            if not form.initial.get("verified_at") and "verified_at" in form.changed_data:
                form.instance.verify(form.cleaned_data["verified_at"])
        return instances


class EmailAddressInline(admin.TabularInline):
    extra = 0
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
    readonly_fields = ["username", "email"]
    inlines = [EmailAddressInline]
    change_password_form = AdminPasswordChange

    def get_search_results(self, request, queryset, search_term):
        queryset, may_have_duplicates = super().get_search_results(request, queryset, search_term)
        term_queries = []
        for bit in smart_split(search_term):
            if bit.startswith(('"', "'")) and bit[0] == bit[-1]:
                bit = unescape_string_literal(bit)
            term_queries.append(Q(email__icontains=bit))
        queryset |= self.model.objects.filter(
            Exists(EmailAddress.objects.filter(*term_queries, user_id=OuterRef("pk")))
        )
        return queryset, may_have_duplicates

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        [email_address_formset] = formsets
        if form.instance.email and not any(is_email_verified(fs) for fs in email_address_formset):
            form.instance.email = ""
            form.instance.save(update_fields=["email"])

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        assert fieldsets[0] == (None, {"fields": ("username", "password")})
        new_fieldsets = copy.deepcopy(fieldsets)
        new_fieldsets[0][1]["fields"] += ("must_reset_password",)
        return new_fieldsets
