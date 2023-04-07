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

from inclusion_connect.oauth_overrides.views import LogoutView
from inclusion_connect.www.login.views import LoginView


urlpatterns = [
    path("admin/", admin.site.urls),
    re_path(r"^accounts/login/$", LoginView.as_view(), name="login"),
    re_path(r"^auth/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    re_path(r"^auth/logout", LogoutView.as_view(), name="oauth2_provider_logout"),
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
