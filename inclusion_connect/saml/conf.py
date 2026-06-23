from django.conf import settings
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_PERSISTENT


# Path of the SSO endpoint, advertised in metadata. The view is wired in a later slice.
SSO_PATH = "/saml/sso"


def build_idp_config(base_url):
    """Build the pysaml2 IdP configuration from Django settings.

    `base_url` is the public scheme://host serving the request, used to build the
    advertised endpoint locations so metadata always reflects the current deployment.
    The signing certificate/key have a lifecycle independent from `oidc.pem` and are
    configured via settings/env.
    """
    sso_location = f"{base_url}{SSO_PATH}"
    conf = {
        "entityid": settings.SAML_IDP_ENTITY_ID,
        "service": {
            "idp": {
                "name": "Inclusion Connect",
                "endpoints": {
                    "single_sign_on_service": [
                        (sso_location, BINDING_HTTP_REDIRECT),
                        (sso_location, BINDING_HTTP_POST),
                    ],
                },
                "name_id_format": [NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_EMAILADDRESS],
            },
        },
        "key_file": settings.SAML_IDP_SIGNING_KEY_FILE,
        "cert_file": settings.SAML_IDP_SIGNING_CERT_FILE,
    }
    config = Config()
    config.load(conf)
    return config
