"""inclusion_connect URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path


urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # Login and registration urls
    re_path(r"^accounts/", include("inclusion_connect.accounts.urls")),
    re_path(r"^accounts/", include("django.contrib.auth.urls")),
    # OIDC urls
    re_path(r"^auth/", include("inclusion_connect.oidc_overrides.urls")),
    re_path(r"^auth/", include("oauth2_provider.urls", namespace="oauth2_provider")),
]

for realm in settings.KEYCLOAK_REALMS:
    urlpatterns.append(
        re_path(
            rf"^realms/{realm}/protocol/openid-connect/",
            include("inclusion_connect.keycloak_compat.urls", namespace=f"keycloak_compat_{realm}"),
        )
    )

if settings.DEBUG and "debug_toolbar" in settings.INSTALLED_APPS:
    import debug_toolbar

    urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
    urlpatterns = [path("__debug__/", include(debug_toolbar.urls))] + urlpatterns
