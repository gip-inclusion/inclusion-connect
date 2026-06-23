from django.contrib import admin
from django.utils.html import format_html_join

from inclusion_connect.saml.models import SamlServiceProvider


@admin.register(SamlServiceProvider)
class SamlServiceProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "entity_id", "require_signed_authn_request")
    list_filter = ("nameid_format", "sign_assertion", "encrypt_assertion", "require_signed_authn_request")
    search_fields = ("name", "entity_id")
    readonly_fields = ("entity_id", "acs_endpoints_display", "created_at", "updated_at")
    fieldsets = (
        (None, {"fields": ("name", "metadata", "entity_id", "acs_endpoints_display")}),
        (
            "Politique de release",
            {"fields": ("nameid_format", "attribute_mapping")},
        ),
        (
            "Sécurité",
            {"fields": ("sign_assertion", "encrypt_assertion", "require_signed_authn_request")},
        ),
        ("Suivi", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="URLs ACS")
    def acs_endpoints_display(self, obj):
        if not obj.pk:
            return "—"
        return format_html_join("\n", "<div>{}</div>", ((url,) for url in obj.acs_endpoints()))
