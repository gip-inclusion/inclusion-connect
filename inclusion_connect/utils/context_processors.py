from django.conf import settings


def expose_settings(request):
    return {"DEMO_MODE": settings.DEMO_MODE}
