import base64

from django.conf import settings
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, samlp
from saml2.attribute_converter import AttributeConverter
from saml2.config import Config
from saml2.s_utils import decode_base64_and_inflate
from saml2.saml import (
    AUTHN_PASSWORD_PROTECTED,
    NAME_FORMAT_URI,
    NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_PERSISTENT,
)
from saml2.server import Server


# Path of the SSO endpoint, advertised in metadata and target of inbound AuthnRequests.
SSO_PATH = "/saml/sso"

# Default attribute release set, mapped to standard URI-format (OID) names so a zero-config
# SP receives interoperable attributes. SIRET/SIREN have no registered OID, so they use an
# IC-namespaced URN. Per-SP overrides live on the model's `attribute_mapping` (a later slice).
ATTRIBUTE_URIS = {
    "email": "urn:oid:0.9.2342.19200300.100.1.3",
    "given_name": "urn:oid:2.5.4.42",
    "family_name": "urn:oid:2.5.4.4",
    "uid": "urn:oid:0.9.2342.19200300.100.1.1",
    "siret": "urn:fr:gouv:saml:attribute:siret",
    "siren": "urn:fr:gouv:saml:attribute:siren",
}

# Authentication context advertised in the assertion: IC always authenticates with a
# password (and enforces TOTP through the post-login middleware before issuing anything).
AUTHN_CONTEXT = {"class_ref": AUTHN_PASSWORD_PROTECTED}


def _idp_conf_dict(base_url):
    """The pysaml2 IdP configuration shared by the metadata and SSO code paths.

    `base_url` is the public scheme://host serving the request, used to build the advertised
    endpoint locations so metadata always reflects the current deployment. The signing
    certificate/key have a lifecycle independent from `oidc.pem` and are configured via settings.
    """
    sso_location = f"{base_url}{SSO_PATH}"
    return {
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


def build_idp_config(base_url):
    """Build the pysaml2 IdP ``Config`` for metadata generation.

    Deliberately free of SP metadata: loading any `metadata` triggers a security context that
    requires the `xmlsec1` binary, which the metadata endpoint must not depend on.
    """
    config = Config()
    config.load(_idp_conf_dict(base_url))
    return config


def build_idp_server(base_url, sp_metadata):
    """Build a pysaml2 ``Server`` that parses AuthnRequests from ``sp_metadata``'s SP and signs
    Responses to it.

    The SP's metadata XML is loaded inline so pysaml2 resolves the SP's ACS and certificates.
    Signing requires the `xmlsec1` binary on PATH (or `SAML_XMLSEC1_BINARY`). The default URI
    attribute converter is prepended so our canonical attribute set is always released under the
    OID names in ``ATTRIBUTE_URIS``.
    """
    conf_dict = _idp_conf_dict(base_url)
    conf_dict["metadata"] = {"inline": [sp_metadata]}
    if settings.SAML_XMLSEC1_BINARY:
        conf_dict["xmlsec_binary"] = settings.SAML_XMLSEC1_BINARY
    config = Config()
    config.load(conf_dict)
    converter = AttributeConverter(NAME_FORMAT_URI)
    converter.from_dict({"identifier": NAME_FORMAT_URI, "to": ATTRIBUTE_URIS})
    config.attribute_converters.insert(0, converter)
    return Server(config=config)


def extract_issuer(saml_request, binding):
    """Read the issuer entityID from an untrusted ``SAMLRequest`` on the given inbound binding.

    The two inbound bindings encode the request differently: Redirect base64s a DEFLATE-compressed
    body, POST base64s the raw XML. Decode accordingly before reading the issuer.

    Used only to look up the registered SP; that SP's own pysaml2 ``Server`` then re-parses and
    validates the request authoritatively before any assertion is issued. Cheap on purpose — no
    Server, no signing context — so unknown/garbage requests are rejected without touching xmlsec1.
    Raises on undecodable input.
    """
    if binding == BINDING_HTTP_REDIRECT:
        xml = decode_base64_and_inflate(saml_request)
    else:
        xml = base64.b64decode(saml_request)
    request = samlp.authn_request_from_string(xml)
    return request.issuer.text if request and request.issuer else None
