from django.http import HttpResponse
from django.views import View
from saml2.metadata import entity_descriptor

from inclusion_connect.logging import log
from inclusion_connect.saml.conf import build_idp_config


LOGGER_NAME = "inclusion_connect.saml"


class MetadataView(View):
    """Serve dynamically generated IdP metadata.

    pysaml2 builds the document from the current config so a signing certificate
    rotation or an endpoint change is always reflected without a manual update.
    """

    def get(self, request, *args, **kwargs):
        base_url = request.build_absolute_uri("/").rstrip("/")
        config = build_idp_config(base_url)
        metadata = str(entity_descriptor(config))
        log(LOGGER_NAME, request, event="metadata")
        return HttpResponse(
            f'<?xml version="1.0" encoding="UTF-8"?>\n{metadata}',
            content_type="application/samlmetadata+xml",
        )
