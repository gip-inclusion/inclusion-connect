import base64
import zlib

from django.conf import settings
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, saml, samlp
from saml2.attribute_converter import AttributeConverter
from saml2.config import Config
from saml2.s_utils import do_ava, factory
from saml2.saml import (
    AUTHN_PASSWORD_PROTECTED,
    NAME_FORMAT_URI,
    NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_PERSISTENT,
)
from saml2.server import Server


SSO_PATH = "/saml/sso"
SLO_PATH = "/saml/slo"

# Default release set under standard URI/OID names. SIRET/SIREN have no registered OID, so they
# use an IC-namespaced URN.
ATTRIBUTE_URIS = {
    "email": "urn:oid:0.9.2342.19200300.100.1.3",
    "given_name": "urn:oid:2.5.4.42",
    "family_name": "urn:oid:2.5.4.4",
    "uid": "urn:oid:0.9.2342.19200300.100.1.1",
    "siret": "urn:fr:gouv:saml:attribute:siret",
    "siren": "urn:fr:gouv:saml:attribute:siren",
}

AUTHN_CONTEXT = {"class_ref": AUTHN_PASSWORD_PROTECTED}


def default_attribute_policy():
    return [(key, name, NAME_FORMAT_URI) for key, name in ATTRIBUTE_URIS.items()]


class _ReleasePolicyConverter(AttributeConverter):
    # Emit each released attribute under its per-SP (emitted_name, name_format). name_format stays
    # NAME_FORMAT_URI only so pysaml2's converter selection picks this converter; the real per-
    # attribute formats live in self.policy.
    def __init__(self, policy):
        super().__init__(NAME_FORMAT_URI)
        self._to = {}
        self._fro = {}
        self.policy = policy

    def to_(self, attrvals):
        attributes = []
        for key, name, name_format in self.policy:
            if key not in attrvals:
                continue
            attributes.append(
                factory(
                    saml.Attribute,
                    name=name,
                    name_format=name_format,
                    friendly_name=key,
                    attribute_value=do_ava(attrvals[key]),
                )
            )
        return attributes


def _idp_conf_dict(base_url):
    sso_location = f"{base_url}{SSO_PATH}"
    slo_location = f"{base_url}{SLO_PATH}"
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
                    "single_logout_service": [
                        (slo_location, BINDING_HTTP_REDIRECT),
                        (slo_location, BINDING_HTTP_POST),
                    ],
                },
                "name_id_format": [NAMEID_FORMAT_PERSISTENT, NAMEID_FORMAT_EMAILADDRESS],
            },
        },
        "key_file": settings.SAML_IDP_SIGNING_KEY_FILE,
        "cert_file": settings.SAML_IDP_SIGNING_CERT_FILE,
    }


def build_idp_config(base_url):
    # Deliberately free of SP metadata: loading any metadata triggers a security context that needs
    # the xmlsec1 binary, which the metadata endpoint must not depend on.
    config = Config()
    config.load(_idp_conf_dict(base_url))
    return config


def build_idp_server(base_url, sp_metadata, want_authn_requests_signed=False, attribute_policy=None):
    conf_dict = _idp_conf_dict(base_url)
    conf_dict["metadata"] = {"inline": [sp_metadata]}
    conf_dict["service"]["idp"]["want_authn_requests_signed"] = want_authn_requests_signed
    if settings.SAML_XMLSEC1_BINARY:
        conf_dict["xmlsec_binary"] = settings.SAML_XMLSEC1_BINARY
    config = Config()
    config.load(conf_dict)
    policy = attribute_policy if attribute_policy is not None else default_attribute_policy()
    config.attribute_converters.insert(0, _ReleasePolicyConverter(policy))
    return Server(config=config)


def verify_authn_request(base_url, sp_metadata, inbound, require_signed, attribute_policy=None):
    # pysaml2 only verifies a Redirect query-string signature when the request is "required to be
    # signed", so force that whenever a Redirect signature is present, else a bad one would slip by.
    must = require_signed or (inbound.binding == BINDING_HTTP_REDIRECT and inbound.signature is not None)
    server = build_idp_server(
        base_url, sp_metadata, want_authn_requests_signed=must, attribute_policy=attribute_policy
    )
    request = server.parse_authn_request(
        inbound.saml_request,
        inbound.binding,
        relay_state=inbound.relay_state,
        sigalg=inbound.sigalg,
        signature=inbound.signature,
    )
    return server, request.message


def verify_logout_request(base_url, sp_metadata, inbound, require_signed):
    must = require_signed or (inbound.binding == BINDING_HTTP_REDIRECT and inbound.signature is not None)
    server = build_idp_server(base_url, sp_metadata, want_authn_requests_signed=must)
    request = server.parse_logout_request(
        inbound.saml_request,
        inbound.binding,
        relay_state=inbound.relay_state,
        sigalg=inbound.sigalg,
        signature=inbound.signature,
    )
    return server, request.message


# Bound an inbound SAMLRequest to defuse a DEFLATE decompression bomb on the Redirect binding.
MAX_SAML_REQUEST_B64 = 100 * 1024
MAX_SAML_REQUEST_XML = 1024 * 1024


def _decode_saml_request(saml_request, binding):
    # Redirect base64s a DEFLATE-compressed body, POST base64s the raw XML. Bounded on both the
    # encoded input and the inflated output.
    if len(saml_request) > MAX_SAML_REQUEST_B64:
        raise ValueError("SAMLRequest exceeds the maximum encoded size.")
    raw = base64.b64decode(saml_request)
    if binding != BINDING_HTTP_REDIRECT:
        return raw
    decompressor = zlib.decompressobj(-15)
    inflated = decompressor.decompress(raw, MAX_SAML_REQUEST_XML)
    if decompressor.unconsumed_tail:
        raise ValueError("SAMLRequest exceeds the maximum inflated size.")
    return inflated


def extract_issuer(saml_request, binding):
    # Read the issuer only to look up the registered SP; that SP's own Server re-parses and validates
    # authoritatively before any assertion. Cheap on purpose — no Server, no xmlsec1.
    request = samlp.authn_request_from_string(_decode_saml_request(saml_request, binding))
    return request.issuer.text if request and request.issuer else None


def extract_logout_issuer(saml_request, binding):
    request = samlp.logout_request_from_string(_decode_saml_request(saml_request, binding))
    return request.issuer.text if request and request.issuer else None
