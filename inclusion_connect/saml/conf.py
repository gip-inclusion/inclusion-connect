import base64

from django.conf import settings
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, saml, samlp
from saml2.attribute_converter import AttributeConverter
from saml2.config import Config
from saml2.s_utils import decode_base64_and_inflate, do_ava, factory
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


def default_attribute_policy():
    """The zero-config release policy: the full canonical set under the standard URI/OID names."""
    return [(key, name, NAME_FORMAT_URI) for key, name in ATTRIBUTE_URIS.items()]


class _ReleasePolicyConverter(AttributeConverter):
    """Emit each released attribute under its per-SP name and NameFormat.

    pysaml2's stock converter maps every attribute to a single NameFormat (the policy's name
    form) and a single name table. This subclass instead carries the SP's resolved
    ``(canonical_key, emitted_name, name_format)`` policy and emits each attribute individually,
    so an SP can release only a subset, rename attributes and mix NameFormats. ``name_format``
    stays ``NAME_FORMAT_URI`` solely so pysaml2's converter selection — which matches on the
    policy's default name form — picks this converter; the real per-attribute formats live in
    ``self.policy``.
    """

    def __init__(self, policy):
        super().__init__(NAME_FORMAT_URI)
        # The base leaves the name tables as None; we only emit (``to_``), but keep them as empty
        # dicts so pysaml2's read-side helpers (``from_format``/``fro``) degrade to "no match"
        # instead of dereferencing None should any path ever consult this converter.
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


def build_idp_server(base_url, sp_metadata, want_authn_requests_signed=False, attribute_policy=None):
    """Build a pysaml2 ``Server`` that parses AuthnRequests from ``sp_metadata``'s SP and signs
    Responses to it.

    The SP's metadata XML is loaded inline so pysaml2 resolves the SP's ACS and certificates.
    Signing requires the `xmlsec1` binary on PATH (or `SAML_XMLSEC1_BINARY`). A
    ``_ReleasePolicyConverter`` is prepended so the released attribute set, names and NameFormats
    follow ``attribute_policy`` (default = the zero-config URI/OID mapping). ``want_authn_requests_signed``
    makes a signature mandatory: pysaml2 rejects a request that carries none (see ``verify_authn_request``).
    """
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
    """Authoritatively parse ``inbound``'s AuthnRequest against ``sp_metadata`` and verify its
    signature. Returns ``(server, message)``; raises ``IncorrectlySigned`` on a bad signature and
    other pysaml2 errors on malformed/expired/replayed input (the caller maps both to a 400).

    ``require_signed`` is the per-SP policy (reject an unsigned request). A present signature is
    always verified, but pysaml2 only checks a Redirect-binding query-string signature when the
    request is "required to be signed" — POST signatures are enveloped in the XML and checked
    whenever present — so force that whenever a Redirect signature is present, else a bad one
    would slip by. ``inbound`` carries the SAMLRequest, binding, RelayState and (Redirect-only)
    sigalg/signature. ``attribute_policy`` carries the SP's release policy onto the returned
    ``server`` so the assertion it later builds honours it.
    """
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
