import datetime
import logging

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.exceptions import ValidationError
from django.urls import reverse
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.mdstore import InMemoryMetaData

from inclusion_connect.saml.models import SamlServiceProvider
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
