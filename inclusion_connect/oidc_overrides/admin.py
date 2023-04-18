from django.contrib import admin
from oauth2_provider import admin as oauth2_admin

from inclusion_connect.oidc_overrides import models


admin.site.unregister(models.Application)


@admin.register(models.Application)
class ApplicationAdmin(oauth2_admin.ApplicationAdmin):
    list_filter = ("client_type", "authorization_grant_type")
