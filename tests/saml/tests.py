import datetime
import logging
import re

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.core.exceptions import ValidationError
from django.urls import reverse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.mdstore import InMemoryMetaData
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_PERSISTENT

from inclusion_connect.saml.conf import ATTRIBUTE_URIS
from inclusion_connect.saml.models import SamlServiceProvider
from inclusion_connect.utils.urls import get_url_params
from tests.asserts import assertRecords
from tests.saml.factories import SamlServiceProviderFactory, build_sp_metadata
from tests.users.factories import UserFactory


IDP_ENTITY_ID = "http://testserver/saml/idp"
SSO_LOCATION = "http://testserver/saml/sso"


def parse_idp_metadata(content):
    # The same library an SP would use to consume our metadata; parsing without error
    # is the well-formedness check.
    mds = InMemoryMetaData(None, None)
    mds.parse(content)
    return mds


class TestMetadata:
    def test_metadata_endpoint(self, client, caplog):
        response = client.get(reverse("saml:metadata"))
        assert response.status_code == 200
        assert response["Content-Type"] == "application/samlmetadata+xml"

        content = response.content.decode()
        # The private signing key must never leak into the published metadata.
        assert "PRIVATE KEY" not in content

        mds = parse_idp_metadata(content)
        assert list(mds.keys()) == [IDP_ENTITY_ID]
        assert len(mds.certs(IDP_ENTITY_ID, "idpsso", "signing")) == 1

        sso = mds.service(IDP_ENTITY_ID, "idpsso_descriptor", "single_sign_on_service")
        assert set(sso) == {BINDING_HTTP_REDIRECT, BINDING_HTTP_POST}
        for [endpoint] in sso.values():
            assert endpoint["location"] == SSO_LOCATION

        assertRecords(caplog, [("inclusion_connect.saml", logging.INFO, {"event": "metadata"})])

    def test_metadata_trailing_slash(self, client):
        assert client.get("/saml/metadata/").status_code == 200

    def test_metadata_reflects_signing_certificate(self, client, settings, tmp_path):
        """Regenerating after a cert change reflects the new certificate."""
        first = parse_idp_metadata(client.get(reverse("saml:metadata")).content.decode())
        [first_cert] = first.certs(IDP_ENTITY_ID, "idpsso", "signing")

        new_cert = tmp_path / "new.crt"
        new_key = tmp_path / "new.key"
        _write_self_signed_cert(new_cert, new_key)
        settings.SAML_IDP_SIGNING_CERT_FILE = str(new_cert)
        settings.SAML_IDP_SIGNING_KEY_FILE = str(new_key)

        second = parse_idp_metadata(client.get(reverse("saml:metadata")).content.decode())
        [second_cert] = second.certs(IDP_ENTITY_ID, "idpsso", "signing")
        assert second_cert != first_cert


class TestSamlServiceProvider:
    def test_registration_parses_entity_id_and_acs(self):
        metadata = build_sp_metadata("https://sp.example.com/saml/metadata", "https://sp.example.com/saml/acs")
        sp = SamlServiceProvider.objects.create(name="Demo SP", metadata=metadata)

        assert sp.entity_id == "https://sp.example.com/saml/metadata"
        assert sp.acs_endpoints() == ["https://sp.example.com/saml/acs"]

    def test_factory_creates_valid_sp(self):
        sp = SamlServiceProviderFactory()
        assert sp.entity_id == SamlServiceProvider.objects.get(pk=sp.pk).entity_id
        assert sp.acs_endpoints()

    def test_require_signed_authn_request_defaults_off(self):
        assert SamlServiceProviderFactory().require_signed_authn_request is False

    def test_default_nameid_format_is_persistent(self):
        assert SamlServiceProviderFactory().nameid_format == SamlServiceProvider.NameIdFormat.PERSISTENT

    @pytest.mark.parametrize(
        "metadata",
        [
            pytest.param("not xml at all", id="garbage"),
            pytest.param("", id="empty"),
            pytest.param("<?xml version='1.0'?><root/>", id="no-entity"),
            pytest.param(
                '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x">'
                '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>'
                "</EntityDescriptor>",
                id="idp-without-acs",
            ),
        ],
    )
    def test_invalid_metadata_is_rejected(self, metadata):
        sp = SamlServiceProvider(name="Bad SP", metadata=metadata)
        with pytest.raises(ValidationError):
            sp.full_clean()

    def test_admin_can_create_sp(self, client):
        client.force_login(UserFactory(is_superuser=True, is_staff=True))
        metadata = build_sp_metadata("https://admin.example.com/saml/metadata", "https://admin.example.com/saml/acs")
        response = client.post(
            reverse("admin:saml_samlserviceprovider_add"),
            {
                "name": "Admin SP",
                "metadata": metadata,
                "nameid_format": SamlServiceProvider.NameIdFormat.PERSISTENT,
                "attribute_mapping": "{}",
                "sign_assertion": "on",
            },
        )
        assert response.status_code == 302
        sp = SamlServiceProvider.objects.get()
        assert sp.entity_id == "https://admin.example.com/saml/metadata"

    def test_admin_rejects_duplicate_entity_id(self, client):
        client.force_login(UserFactory(is_superuser=True, is_staff=True))
        metadata = build_sp_metadata("https://dup.example.com/saml/metadata", "https://dup.example.com/saml/acs")
        SamlServiceProvider.objects.create(name="First", metadata=metadata)
        response = client.post(
            reverse("admin:saml_samlserviceprovider_add"),
            {
                "name": "Second",
                "metadata": metadata,
                "nameid_format": SamlServiceProvider.NameIdFormat.PERSISTENT,
                "attribute_mapping": "{}",
            },
        )
        assert response.status_code == 200
        assert SamlServiceProvider.objects.count() == 1
        assert "est déjà enregistré" in response.content.decode()

    def test_admin_rejects_invalid_metadata(self, client):
        client.force_login(UserFactory(is_superuser=True, is_staff=True))
        response = client.post(
            reverse("admin:saml_samlserviceprovider_add"),
            {
                "name": "Bad SP",
                "metadata": "not xml",
                "nameid_format": SamlServiceProvider.NameIdFormat.PERSISTENT,
                "attribute_mapping": "{}",
            },
        )
        assert response.status_code == 200
        assert SamlServiceProvider.objects.count() == 0
        assert "Métadonnées SAML invalides" in response.content.decode()


SP_ENTITY_ID = "https://sp.example.com/saml/metadata"
SP_ACS_URL = "https://sp.example.com/saml/acs"


def build_sp_client(client, want_assertions_signed=True):
    """A pysaml2 SP configured as the test counterparty.

    It loads our published IdP metadata (fetched via `client`) so it discovers the SSO endpoint,
    sends AuthnRequests there, and verifies the signature on the assertion we return.
    """
    idp_metadata = client.get(reverse("saml:metadata")).content.decode()
    conf = SPConfig()
    conf.load(
        {
            "entityid": SP_ENTITY_ID,
            "service": {
                "sp": {
                    "endpoints": {"assertion_consumer_service": [(SP_ACS_URL, BINDING_HTTP_POST)]},
                    "want_assertions_signed": want_assertions_signed,
                    "want_response_signed": False,
                    "allow_unsolicited": False,
                },
            },
            "metadata": {"inline": [idp_metadata]},
        }
    )
    return Saml2Client(config=conf)


def authn_request_query(sp_client, relay_state=""):
    """Build a Redirect-binding AuthnRequest and return (request_id, query_params)."""
    request_id, info = sp_client.prepare_for_authenticate(relay_state=relay_state)
    return request_id, get_url_params(dict(info["headers"])["Location"])


def form_field(content, name):
    """Extract a hidden form field value from a pysaml2 auto-POST page."""
    return re.search(rf'name="{name}" value="([^"]+)"', content)[1]


def parsed_assertion_attributes(assertion):
    return {
        attr.name: ([v.text for v in attr.attribute_value], attr.name_format)
        for attr in assertion.attribute_statement[0].attribute
    }


def register_sp(**kwargs):
    kwargs.setdefault("name", "Demo SP")
    return SamlServiceProvider.objects.create(metadata=build_sp_metadata(SP_ENTITY_ID, SP_ACS_URL), **kwargs)


class TestSso:
    def _run_sso(self, client, user, sp_client, relay_state=""):
        """Drive the SP-initiated round trip; return (page_content, parsed authn_response)."""
        request_id, params = authn_request_query(sp_client, relay_state=relay_state)
        client.force_login(user)
        content = client.get(reverse("saml:sso"), params).content.decode()
        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        return content, authn_response

    def test_authenticated_happy_path(self, client, caplog):
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)
        caplog.clear()
        content, authn_response = self._run_sso(client, user, sp_client)

        # The Response is delivered as an auto-submitting POST form to the SP's ACS.
        assert f'action="{SP_ACS_URL}"' in content

        # Signature validity is enforced by parse_authn_request_response (want_assertions_signed);
        # the assertion carries a signature element.
        assert authn_response.assertion.signature is not None

        # Audience is restricted to the requesting SP.
        audience = authn_response.assertion.conditions.audience_restriction[0].audience[0].text
        assert audience == SP_ENTITY_ID

        # NameID is persistent and equals User.username (= the OIDC sub).
        assert authn_response.name_id.format == NAMEID_FORMAT_PERSISTENT
        assert authn_response.name_id.text == str(user.username)

        # Default attribute set, released under standard URI-format (OID) names.
        assert parsed_assertion_attributes(authn_response.assertion) == {
            ATTRIBUTE_URIS["email"]: ([user.email], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["given_name"]: ([user.first_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["family_name"]: ([user.last_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["uid"]: ([str(user.pk)], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siret"]: ([settings.SIRET], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siren"]: ([settings.SIREN], NAME_FORMAT_URI),
        }

        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "sso_request", "service_provider": SP_ENTITY_ID, "user": user.email},
                ),
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "sso_assertion", "service_provider": SP_ENTITY_ID, "user": user.email},
                ),
            ],
        )

    def test_relay_state_round_trips(self, client):
        user = UserFactory()
        register_sp()
        content, _ = self._run_sso(client, user, build_sp_client(client), relay_state="/deep/link")
        assert form_field(content, "RelayState") == "/deep/link"

    def test_email_nameid_format_override(self, client):
        user = UserFactory()
        register_sp(name="Email SP", nameid_format=SamlServiceProvider.NameIdFormat.EMAIL)
        _, authn_response = self._run_sso(client, user, build_sp_client(client))

        assert authn_response.name_id.format == NAMEID_FORMAT_EMAILADDRESS
        assert authn_response.name_id.text == user.email

    @pytest.mark.filterwarnings("ignore:The SAML service provider accepts unsigned")
    def test_unsigned_assertion_when_sign_disabled(self, client):
        user = UserFactory()
        register_sp(name="Unsigned SP", sign_assertion=False)
        _, authn_response = self._run_sso(client, user, build_sp_client(client, want_assertions_signed=False))

        assert authn_response.assertion.signature is None

    def test_unauthenticated_redirects_to_login(self, client):
        register_sp()
        _, params = authn_request_query(build_sp_client(client))

        response = client.get(reverse("saml:sso"), params)
        assert response.status_code == 302
        assert response.url.startswith(reverse("accounts:login"))

    def test_unknown_service_provider_is_rejected(self, client, caplog):
        user = UserFactory()
        # No SamlServiceProvider registered for this issuer.
        _, params = authn_request_query(build_sp_client(client))

        client.force_login(user)
        caplog.clear()
        response = client.get(reverse("saml:sso"), params)
        assert response.status_code == 400
        # Drop the generic django.request "Bad Request" warnings the 400 triggers.
        caplog.records[:] = [r for r in caplog.records if r.name == "inclusion_connect.saml"]
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "sso_request_error", "error": "unknown_sp", "service_provider": SP_ENTITY_ID},
                )
            ],
        )

    def test_missing_authn_request_is_rejected(self, client):
        client.force_login(UserFactory())
        assert client.get(reverse("saml:sso")).status_code == 400

    def test_malformed_authn_request_is_rejected(self, client):
        # A non-empty but undecodable SAMLRequest must yield a clean 400, never a 500.
        client.force_login(UserFactory())
        response = client.get(reverse("saml:sso"), {"SAMLRequest": "not-a-real-saml-request"})
        assert response.status_code == 400


def _write_self_signed_cert(cert_path, key_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Inclusion Connect SAML rotated")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2035, 1, 1))
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
