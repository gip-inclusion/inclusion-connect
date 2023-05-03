from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.core.exceptions import ValidationError
from django.db.models import Exists, F, OuterRef, Q
from django.forms.formsets import DELETION_FIELD_NAME
from django.utils.text import smart_split, unescape_string_literal

from .models import EmailAddress, User


class EmailAddressInlineForm(forms.ModelForm):
    def save(self, commit=True):
        instance = super().save(commit=commit)
        if not self.initial.get("verified_at") and "verified_at" in self.changed_data:
            self.instance.verify(self.cleaned_data["verified_at"])
        return instance


def is_email_verified(form):
    return not form.cleaned_data.get(DELETION_FIELD_NAME) and form.cleaned_data.get("verified_at")


class EmailAddressInlineFormSet(forms.BaseInlineFormSet):
    def clean(self):
        super().clean()
        verified_addresses = 0
        for form in self.forms:
            if is_email_verified(form):
                verified_addresses += 1
            if verified_addresses >= 2:
                raise ValidationError("L’utilisateur ne peut avoir qu’un seul e-mail vérifié.")


class EmailAddressInline(admin.TabularInline):
    extra = 0
    model = EmailAddress
    readonly_fields = ["created_at"]
    form = EmailAddressInlineForm
    formset = EmailAddressInlineFormSet
    fields = ["email", "verified_at", "created_at"]
    ordering = [F("verified_at").desc(nulls_last=True), "email"]


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    model = User
    readonly_fields = ["username", "email"]
    inlines = [EmailAddressInline]

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
