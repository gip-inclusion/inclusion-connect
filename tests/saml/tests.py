import base64
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
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice
from pytest_django.asserts import assertRedirects
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.mdstore import InMemoryMetaData
from saml2.saml import (
    NAME_FORMAT_BASIC,
    NAME_FORMAT_URI,
    NAMEID_FORMAT_EMAILADDRESS,
    NAMEID_FORMAT_PERSISTENT,
    NameID,
)

from inclusion_connect.saml.conf import ATTRIBUTE_URIS
from inclusion_connect.saml.models import SamlServiceProvider, UserSamlServiceProviderLink
from inclusion_connect.saml.views import SAML_SESSION_KEY
from inclusion_connect.utils.urls import get_url_params
from tests.asserts import assertRecords
from tests.helpers import confirm_otp_flow
from tests.saml.factories import SamlServiceProviderFactory, build_sp_metadata
from tests.users.factories import DEFAULT_PASSWORD, UserFactory


IDP_ENTITY_ID = "http://testserver/saml/idp"
SSO_LOCATION = "http://testserver/saml/sso"
SLO_LOCATION = "http://testserver/saml/slo"


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

    def test_metadata_advertises_slo_endpoint(self, client):
        mds = parse_idp_metadata(client.get(reverse("saml:metadata")).content.decode())
        slo = mds.service(IDP_ENTITY_ID, "idpsso_descriptor", "single_logout_service")
        assert set(slo) == {BINDING_HTTP_REDIRECT, BINDING_HTTP_POST}
        for [endpoint] in slo.values():
            assert endpoint["location"] == SLO_LOCATION

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
SP_SLO_URL = "https://sp.example.com/saml/slo"


def build_sp_client(client, want_assertions_signed=True, key_file=None, cert_file=None, encryption_cert_file=None):
    """A pysaml2 SP configured as the test counterparty.

    It loads our published IdP metadata (fetched via `client`) so it discovers the SSO endpoint,
    sends AuthnRequests there, and verifies the signature on the assertion we return. Passing a
    key/cert makes it sign its AuthnRequests (query-string signature on Redirect, enveloped XML
    signature on POST). Passing ``encryption_cert_file`` gives the SP the matching keypair so it
    can decrypt an assertion the IdP encrypted to that cert.
    """
    idp_metadata = client.get(reverse("saml:metadata")).content.decode()
    sp = {
        "endpoints": {
            "assertion_consumer_service": [(SP_ACS_URL, BINDING_HTTP_POST)],
            # The SP's own SLS endpoint must match the Destination the IdP sets on the
            # LogoutResponse, else pysaml2 rejects the response on the return trip.
            "single_logout_service": [
                (SP_SLO_URL, BINDING_HTTP_REDIRECT),
                (SP_SLO_URL, BINDING_HTTP_POST),
            ],
        },
        "want_assertions_signed": want_assertions_signed,
        "want_response_signed": False,
        "allow_unsolicited": False,
    }
    conf_dict = {
        "entityid": SP_ENTITY_ID,
        "service": {"sp": sp},
        "metadata": {"inline": [idp_metadata]},
    }
    if cert_file:
        sp["authn_requests_signed"] = True
        conf_dict["key_file"] = key_file
        conf_dict["cert_file"] = cert_file
    if encryption_cert_file:
        conf_dict["encryption_keypairs"] = [{"key_file": key_file, "cert_file": encryption_cert_file}]
    conf = SPConfig()
    conf.load(conf_dict)
    return Saml2Client(config=conf)


def authn_request_query(sp_client, relay_state=""):
    """Build a Redirect-binding AuthnRequest and return (request_id, query_params)."""
    request_id, info = sp_client.prepare_for_authenticate(relay_state=relay_state)
    return request_id, get_url_params(dict(info["headers"])["Location"])


def authn_request_post(sp_client, relay_state=""):
    """Build a POST-binding AuthnRequest and return (request_id, form_params)."""
    request_id, info = sp_client.prepare_for_authenticate(relay_state=relay_state, binding=BINDING_HTTP_POST)
    form = info["data"]
    params = {"SAMLRequest": form_field(form, "SAMLRequest")}
    if relay_state:
        params["RelayState"] = form_field(form, "RelayState")
    return request_id, params


def form_field(content, name):
    """Extract a hidden form field value from a pysaml2 auto-POST page."""
    return re.search(rf'name="{name}" value="([^"]+)"', content)[1]


def parsed_assertion_attributes(assertion):
    return {
        attr.name: ([v.text for v in attr.attribute_value], attr.name_format)
        for attr in assertion.attribute_statement[0].attribute
    }


def register_sp(slo_url=None, key_file=None, cert_file=None, encryption_cert_file=None, **kwargs):
    kwargs.setdefault("name", "Demo SP")
    metadata = build_sp_metadata(
        SP_ENTITY_ID,
        SP_ACS_URL,
        slo_url=slo_url,
        key_file=key_file,
        cert_file=cert_file,
        encryption_cert_file=encryption_cert_file,
    )
    return SamlServiceProvider.objects.create(metadata=metadata, **kwargs)


def logout_request(sp_client, name_id_text, binding=BINDING_HTTP_REDIRECT, relay_state=""):
    """Build an SP-initiated LogoutRequest and return (request_id, request params) for ``binding``."""
    idp_slo = sp_client.metadata.single_logout_service(IDP_ENTITY_ID, binding, "idpsso")[0]["location"]
    name_id = NameID(format=NAMEID_FORMAT_PERSISTENT, text=name_id_text)
    request_id, request = sp_client.create_logout_request(idp_slo, IDP_ENTITY_ID, name_id=name_id)
    http_args = sp_client.apply_binding(binding, str(request), idp_slo, relay_state, response=False)
    if binding == BINDING_HTTP_REDIRECT:
        return request_id, get_url_params(dict(http_args["headers"])["Location"])
    form = http_args["data"]
    params = {"SAMLRequest": form_field(form, "SAMLRequest")}
    if relay_state:
        params["RelayState"] = form_field(form, "RelayState")
    return request_id, params


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
        _, params = authn_request_query(build_sp_client(client), relay_state="/deep/link")

        response = client.get(reverse("saml:sso"), params)
        assert response.status_code == 302
        assert response.url.startswith(reverse("accounts:login"))

        # The validated request is stashed and the post-login flow points at the continue URL.
        stashed = client.session[SAML_SESSION_KEY]
        assert stashed["SAMLRequest"] == params["SAMLRequest"]
        assert stashed["RelayState"] == "/deep/link"
        assert stashed["binding"] == BINDING_HTTP_REDIRECT
        assert client.session["next_url"] == reverse("saml:sso_continue")

    def test_unauthenticated_login_otp_gate_then_assertion(self, client):
        # A brand-new user still owes a confirmed TOTP device: the gate must hold the assertion.
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)
        request_id, params = authn_request_query(sp_client, relay_state="/deep/link")

        login_url = reverse("accounts:login")
        continue_url = reverse("saml:sso_continue")

        # 1. Unauthenticated AuthnRequest bounces to login with the request stashed.
        response = client.get(reverse("saml:sso"), params)
        assert response.status_code == 302
        assert response.url.startswith(login_url)

        # 2. Password alone does not clear the mandatory TOTP gate: the continue URL is itself
        #    gated, so no assertion is issued until OTP is confirmed.
        response = client.post(login_url, {"email": user.email, "password": DEFAULT_PASSWORD})
        device = TOTPDevice.objects.get()
        otp_url = reverse("accounts:otp_confirm_device", args=(device.pk,))
        assertRedirects(response, otp_url)
        gated = client.get(continue_url)
        assertRedirects(gated, otp_url, fetch_redirect_response=False)
        assert SAML_SESSION_KEY in client.session  # request still pending

        # 3. Clearing the TOTP gate resumes the flow at the continue URL.
        response, _ = confirm_otp_flow(client, response)
        assertRedirects(response, continue_url, fetch_redirect_response=False)

        # 4. The assertion is built and auto-POSTed to the SP's ACS, RelayState intact.
        content = client.get(continue_url).content.decode()
        assert f'action="{SP_ACS_URL}"' in content
        assert form_field(content, "RelayState") == "/deep/link"
        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.assertion.signature is not None
        assert authn_response.name_id.format == NAMEID_FORMAT_PERSISTENT
        assert authn_response.name_id.text == str(user.username)
        assert SAML_SESSION_KEY not in client.session  # consumed

    @pytest.mark.parametrize(
        "user_kwargs,gate_url_name",
        [
            pytest.param({"password_is_temporary": True}, "accounts:change_temporary_password", id="temporary"),
            pytest.param({"password_is_too_weak": True}, "accounts:change_weak_password", id="weak"),
        ],
    )
    def test_password_gate_blocks_assertion(self, client, user_kwargs, gate_url_name):
        # OTP-cleared but a password change still pending: the assertion must wait. The gate is
        # enforced by post_login_actions on the continue URL, independent of the login mechanism.
        user = UserFactory(**user_kwargs)
        device = TOTPDevice.objects.create(user=user, confirmed=True)
        register_sp()
        _, params = authn_request_query(build_sp_client(client))

        continue_url = reverse("saml:sso_continue")
        client.get(reverse("saml:sso"), params)  # stash the request
        client.force_login(user, device=device)  # authenticated + OTP-verified

        gated = client.get(continue_url)
        assertRedirects(gated, reverse(gate_url_name), fetch_redirect_response=False)
        assert SAML_SESSION_KEY in client.session  # no assertion issued

    def test_continue_without_stashed_request_is_rejected(self, client):
        client.force_login(UserFactory())
        assert client.get(reverse("saml:sso_continue")).status_code == 400

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


class TestAttributeReleasePolicy:
    def _run_sso(self, client, user, sp_client):
        request_id, params = authn_request_query(sp_client)
        client.force_login(user)
        content = client.get(reverse("saml:sso"), params).content.decode()
        return sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )

    def test_released_subset_only(self, client):
        # Only the keys present in the mapping are released; the rest of the canonical set is withheld.
        user = UserFactory()
        register_sp(name="Subset SP", attribute_mapping={"email": {}, "given_name": {}})
        authn_response = self._run_sso(client, user, build_sp_client(client))

        assert parsed_assertion_attributes(authn_response.assertion) == {
            ATTRIBUTE_URIS["email"]: ([user.email], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["given_name"]: ([user.first_name], NAME_FORMAT_URI),
        }

    def test_name_and_name_format_overrides(self, client):
        # Per-attribute name and NameFormat overrides are honored; an entry with no override keeps
        # the default URI name/format.
        user = UserFactory()
        register_sp(
            name="Override SP",
            attribute_mapping={
                "email": {"name": "mail", "name_format": NAME_FORMAT_BASIC},
                "given_name": {"name": "firstName"},
                "family_name": {"name_format": NAME_FORMAT_BASIC},
            },
        )
        authn_response = self._run_sso(client, user, build_sp_client(client))

        assert parsed_assertion_attributes(authn_response.assertion) == {
            "mail": ([user.email], NAME_FORMAT_BASIC),
            "firstName": ([user.first_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["family_name"]: ([user.last_name], NAME_FORMAT_BASIC),
        }

    def test_empty_mapping_keeps_default_uri_release(self, client):
        # Zero-config: no mapping → the full canonical set under the default URI/OID names.
        user = UserFactory()
        register_sp(name="Default SP", attribute_mapping={})
        authn_response = self._run_sso(client, user, build_sp_client(client))

        assert parsed_assertion_attributes(authn_response.assertion) == {
            ATTRIBUTE_URIS["email"]: ([user.email], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["given_name"]: ([user.first_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["family_name"]: ([user.last_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["uid"]: ([str(user.pk)], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siret"]: ([settings.SIRET], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siren"]: ([settings.SIREN], NAME_FORMAT_URI),
        }

    @pytest.mark.parametrize(
        "mapping,message",
        [
            pytest.param({"unknown": {}}, "Attribut inconnu", id="unknown-key"),
            pytest.param({"email": "mail"}, "doit être un objet", id="value-not-object"),
            pytest.param({"email": {"format": "x"}}, "Clés non supportées", id="unknown-override-key"),
            pytest.param([], None, id="not-a-dict"),
        ],
    )
    def test_invalid_mapping_is_rejected(self, mapping, message):
        sp = SamlServiceProvider(
            name="Bad mapping",
            metadata=build_sp_metadata(SP_ENTITY_ID, SP_ACS_URL),
            attribute_mapping=mapping,
        )
        with pytest.raises(ValidationError) as exc:
            sp.full_clean()
        if message:
            assert message in str(exc.value)


class TestSsoHttpPostBinding:
    def test_authenticated_happy_path_over_post(self, client):
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)
        request_id, params = authn_request_post(sp_client, relay_state="/deep/link")

        client.force_login(user)
        content = client.post(reverse("saml:sso"), params).content.decode()

        # Same outbound delivery as the Redirect path: auto-POST form to the SP's ACS.
        assert f'action="{SP_ACS_URL}"' in content
        assert form_field(content, "RelayState") == "/deep/link"

        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.assertion.signature is not None
        assert authn_response.name_id.format == NAMEID_FORMAT_PERSISTENT
        assert authn_response.name_id.text == str(user.username)

    def test_unauthenticated_post_login_then_assertion(self, client):
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)
        request_id, params = authn_request_post(sp_client, relay_state="/deep/link")

        # 1. Unauthenticated POST bounces to login with the request stashed under the POST binding.
        response = client.post(reverse("saml:sso"), params)
        assert response.status_code == 302
        assert response.url.startswith(reverse("accounts:login"))
        stashed = client.session[SAML_SESSION_KEY]
        assert stashed["binding"] == BINDING_HTTP_POST

        # 2. Login + OTP confirmation clears the gate and resumes at the continue URL.
        continue_url = reverse("saml:sso_continue")
        response = client.post(reverse("accounts:login"), {"email": user.email, "password": DEFAULT_PASSWORD})
        response, _ = confirm_otp_flow(client, response)
        assertRedirects(response, continue_url, fetch_redirect_response=False)

        # 3. The replayed POST-binding request yields the same signed assertion.
        content = client.get(continue_url).content.decode()
        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.assertion.signature is not None
        assert authn_response.name_id.text == str(user.username)
        assert SAML_SESSION_KEY not in client.session

    def test_post_is_csrf_exempt(self, client):
        # The SP auto-submits cross-site without a Django CSRF token; enforcing CSRF would 403 a
        # legitimate AuthnRequest. A registered request must reach the SSO engine, not be blocked.
        user = UserFactory()
        register_sp()
        _, params = authn_request_post(build_sp_client(client))

        csrf_client = client.__class__(enforce_csrf_checks=True)
        csrf_client.force_login(user)
        response = csrf_client.post(reverse("saml:sso"), params)
        assert response.status_code == 200
        assert f'action="{SP_ACS_URL}"' in response.content.decode()


BOTH_BINDINGS = [
    pytest.param(BINDING_HTTP_REDIRECT, id="redirect"),
    pytest.param(BINDING_HTTP_POST, id="post"),
]


def _make_keypair(tmp_path, stem):
    cert, key = tmp_path / f"{stem}.crt", tmp_path / f"{stem}.key"
    _write_self_signed_cert(cert, key)
    return str(key), str(cert)


def assert_invalid_signature_logged(caplog):
    saml_logs = [r.msg for r in caplog.records if r.name == "inclusion_connect.saml"]
    assert {
        "event": "sso_request_error",
        "error": "invalid_signature",
        "service_provider": SP_ENTITY_ID,
        "ip_address": "127.0.0.1",
    } in saml_logs


class TestAuthnRequestSignatureVerification:
    def _authn_request(self, sp_client, binding, relay_state=""):
        if binding == BINDING_HTTP_REDIRECT:
            return authn_request_query(sp_client, relay_state=relay_state)
        return authn_request_post(sp_client, relay_state=relay_state)

    def _send(self, client, binding, params):
        if binding == BINDING_HTTP_REDIRECT:
            return client.get(reverse("saml:sso"), params)
        return client.post(reverse("saml:sso"), params)

    @pytest.mark.parametrize("binding", BOTH_BINDINGS)
    def test_valid_signature_accepted(self, client, tmp_path, binding):
        user = UserFactory()
        key_file, cert_file = _make_keypair(tmp_path, "sp")
        register_sp(key_file=key_file, cert_file=cert_file)
        sp_client = build_sp_client(client, key_file=key_file, cert_file=cert_file)
        request_id, params = self._authn_request(sp_client, binding)

        client.force_login(user)
        response = self._send(client, binding, params)
        assert response.status_code == 200
        authn_response = sp_client.parse_authn_request_response(
            form_field(response.content.decode(), "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.name_id.text == str(user.username)

    @pytest.mark.parametrize("binding", BOTH_BINDINGS)
    def test_required_and_absent_rejected(self, client, binding, caplog):
        # Flag on but the SP sends an unsigned request: rejected, logged, no assertion.
        user = UserFactory()
        register_sp(require_signed_authn_request=True)
        sp_client = build_sp_client(client)
        _, params = self._authn_request(sp_client, binding)

        client.force_login(user)
        caplog.clear()
        response = self._send(client, binding, params)
        assert response.status_code == 400
        assert "SAMLResponse" not in response.content.decode()
        assert_invalid_signature_logged(caplog)

    @pytest.mark.parametrize("binding", BOTH_BINDINGS)
    @pytest.mark.parametrize("require_signed", [True, False], ids=["required", "flag-off"])
    def test_invalid_signature_rejected(self, client, tmp_path, binding, require_signed, caplog):
        # Metadata advertises cert A; the SP signs with key B → verification fails. A bad signature
        # is rejected on both bindings whether or not the SP is required to sign.
        user = UserFactory()
        good_key, good_cert = _make_keypair(tmp_path, "good")
        other_key, _ = _make_keypair(tmp_path, "other")
        register_sp(key_file=good_key, cert_file=good_cert, require_signed_authn_request=require_signed)
        sp_client = build_sp_client(client, key_file=other_key, cert_file=good_cert)
        _, params = self._authn_request(sp_client, binding)

        client.force_login(user)
        caplog.clear()
        response = self._send(client, binding, params)
        assert response.status_code == 400
        assert "SAMLResponse" not in response.content.decode()
        # Pin the rejection to the signature-verification path, not some other 400.
        assert_invalid_signature_logged(caplog)

    @pytest.mark.parametrize("binding", BOTH_BINDINGS)
    def test_required_signature_survives_login_resume(self, client, tmp_path, binding):
        # An unauthenticated, validly-signed request must still verify after the login detour: the
        # Redirect query-string signature is carried across the session, the POST enveloped one
        # rides in the replayed XML.
        user = UserFactory()
        key_file, cert_file = _make_keypair(tmp_path, "sp")
        register_sp(key_file=key_file, cert_file=cert_file, require_signed_authn_request=True)
        sp_client = build_sp_client(client, key_file=key_file, cert_file=cert_file)
        request_id, params = self._authn_request(sp_client, binding, relay_state="/deep/link")

        continue_url = reverse("saml:sso_continue")
        self._send(client, binding, params)  # stash
        client.force_login(user, device=TOTPDevice.objects.create(user=user, confirmed=True))

        content = client.get(continue_url).content.decode()
        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.name_id.text == str(user.username)


class TestAssertionEncryption:
    """Per-SP, metadata-driven assertion encryption (slice 8).

    Encryption is layered on top of the default signed assertion only when the SP's metadata
    advertises an encryption certificate — there is no manual blanket toggle.
    """

    def _run_sso(self, client, user, sp_client):
        request_id, params = authn_request_query(sp_client)
        client.force_login(user)
        content = client.get(reverse("saml:sso"), params).content.decode()
        saml_response = form_field(content, "SAMLResponse")
        authn_response = sp_client.parse_authn_request_response(
            saml_response, BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        return saml_response, authn_response

    def test_assertion_encrypted_when_metadata_advertises_cert(self, client, tmp_path):
        # SP metadata carries an encryption cert → the assertion is encrypted to it. The SP holds
        # the matching key, decrypts, and recovers an intact, signed assertion (NameID + attributes).
        user = UserFactory()
        enc_key, enc_cert = _make_keypair(tmp_path, "enc")
        register_sp(key_file=enc_key, encryption_cert_file=enc_cert)
        sp_client = build_sp_client(client, key_file=enc_key, encryption_cert_file=enc_cert)

        raw_response, authn_response = self._run_sso(client, user, sp_client)

        # The wire response carries an EncryptedAssertion, not a cleartext one.
        decoded = base64.b64decode(raw_response).decode()
        assert "EncryptedAssertion" in decoded
        assert "AttributeStatement" not in decoded

        assert authn_response.assertion.signature is not None
        assert authn_response.name_id.format == NAMEID_FORMAT_PERSISTENT
        assert authn_response.name_id.text == str(user.username)
        assert parsed_assertion_attributes(authn_response.assertion) == {
            ATTRIBUTE_URIS["email"]: ([user.email], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["given_name"]: ([user.first_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["family_name"]: ([user.last_name], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["uid"]: ([str(user.pk)], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siret"]: ([settings.SIRET], NAME_FORMAT_URI),
            ATTRIBUTE_URIS["siren"]: ([settings.SIREN], NAME_FORMAT_URI),
        }

    def test_no_encryption_without_cert_in_metadata(self, client):
        # No encryption cert advertised → the SP receives the normal signed (cleartext) assertion.
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)

        raw_response, authn_response = self._run_sso(client, user, sp_client)

        decoded = base64.b64decode(raw_response).decode()
        assert "EncryptedAssertion" not in decoded
        assert authn_response.assertion.signature is not None
        assert authn_response.name_id.text == str(user.username)

    def test_metadata_drives_encryption_flag(self, client, tmp_path):
        _, enc_cert = _make_keypair(tmp_path, "enc")
        with_cert = register_sp(encryption_cert_file=enc_cert)
        assert with_cert.encrypts_assertions() is True

        SamlServiceProvider.objects.all().delete()
        without_cert = register_sp()
        assert without_cert.encrypts_assertions() is False


class TestLocalSlo:
    """Local Single Logout (slice 9): an SP-initiated LogoutRequest terminates the IC session
    and gets a LogoutResponse, with no propagation to other SPs."""

    def test_slo_terminates_session_and_returns_response(self, client, caplog):
        user = UserFactory()
        register_sp(slo_url=SP_SLO_URL)
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, str(user.username), relay_state="/back")

        client.force_login(user)
        caplog.clear()
        response = client.get(reverse("saml:slo"), params)

        # The LogoutResponse is delivered back to the SP's SLS over the Redirect binding.
        assert response.status_code == 302
        assert response.url.startswith(SP_SLO_URL)
        return_params = get_url_params(response.url)
        assert return_params["RelayState"] == "/back"

        logout_response = sp_client.parse_logout_request_response(return_params["SAMLResponse"], BINDING_HTTP_REDIRECT)
        assert logout_response.status_ok()

        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "slo_request", "service_provider": SP_ENTITY_ID, "user": user.email},
                ),
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "slo_response", "service_provider": SP_ENTITY_ID, "user": user.email},
                ),
            ],
        )

    def test_slo_over_post_binding(self, client):
        user = UserFactory()
        register_sp(slo_url=SP_SLO_URL)
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, str(user.username), binding=BINDING_HTTP_POST, relay_state="/back")

        client.force_login(user)
        content = client.post(reverse("saml:slo"), params).content.decode()

        # POST binding: the response comes back as an auto-POST form to the SP's SLS.
        assert f'action="{SP_SLO_URL}"' in content
        assert form_field(content, "RelayState") == "/back"
        logout_response = sp_client.parse_logout_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST
        )
        assert logout_response.status_ok()

    def test_re_sso_requires_reauth_after_slo(self, client):
        user = UserFactory()
        register_sp(slo_url=SP_SLO_URL)
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, str(user.username))

        client.force_login(user)
        assert client.get(reverse("saml:slo"), params).status_code == 302

        # The session is gone, so a fresh SSO attempt bounces to login instead of issuing an assertion.
        _, authn_params = authn_request_query(sp_client)
        response = client.get(reverse("saml:sso"), authn_params)
        assert response.status_code == 302
        assert response.url.startswith(reverse("accounts:login"))

    def test_slo_unknown_service_provider_is_rejected(self, client, caplog):
        user = UserFactory()
        # No SamlServiceProvider registered for this issuer.
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, str(user.username))

        client.force_login(user)
        caplog.clear()
        response = client.get(reverse("saml:slo"), params)
        assert response.status_code == 400
        caplog.records[:] = [r for r in caplog.records if r.name == "inclusion_connect.saml"]
        assertRecords(
            caplog,
            [
                (
                    "inclusion_connect.saml",
                    logging.INFO,
                    {"event": "slo_request_error", "error": "unknown_sp", "service_provider": SP_ENTITY_ID},
                )
            ],
        )

    def test_slo_for_other_subject_does_not_terminate_session(self, client):
        # A forged LogoutRequest naming a different (or unknown) NameID must NOT log out the
        # browser's user: the endpoint is CSRF-exempt and accepts unsigned requests, so without the
        # NameID check any registered SP could force-log-out an arbitrary user. A valid Success
        # LogoutResponse is still returned, but the session stays alive.
        user = UserFactory()
        register_sp(slo_url=SP_SLO_URL)
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, "someone-else")

        client.force_login(user)
        response = client.get(reverse("saml:slo"), params)
        assert response.status_code == 302
        logout_response = sp_client.parse_logout_request_response(
            get_url_params(response.url)["SAMLResponse"], BINDING_HTTP_REDIRECT
        )
        assert logout_response.status_ok()

        # The session survives: a fresh SSO issues an assertion without bouncing to login.
        request_id, authn_params = authn_request_query(sp_client)
        content = client.get(reverse("saml:sso"), authn_params).content.decode()
        authn_response = sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )
        assert authn_response.name_id.text == str(user.username)

    def test_slo_missing_request_is_rejected(self, client):
        client.force_login(UserFactory())
        assert client.get(reverse("saml:slo")).status_code == 400

    def test_slo_completes_despite_pending_post_login_gate(self, client):
        # A logout must go through even when a post-login gate (here a temporary password) is still
        # pending: SLO is whitelisted in post_login_actions, so the request reaches the view and
        # terminates the session instead of bouncing to the gate.
        user = UserFactory(password_is_temporary=True)
        register_sp(slo_url=SP_SLO_URL)
        sp_client = build_sp_client(client)
        _, params = logout_request(sp_client, str(user.username))

        client.force_login(user, device=TOTPDevice.objects.create(user=user, confirmed=True))
        response = client.get(reverse("saml:slo"), params)

        # Redirected to the SP's SLS with a LogoutResponse, not to the change-password gate.
        assert response.status_code == 302
        assert response.url.startswith(SP_SLO_URL)
        logout_response = sp_client.parse_logout_request_response(
            get_url_params(response.url)["SAMLResponse"], BINDING_HTTP_REDIRECT
        )
        assert logout_response.status_ok()
        assert "_auth_user_id" not in client.session


class TestUserSamlServiceProviderLink:
    """Audit link (slice 10): each successful assertion records which SP the user used and when."""

    def _run_sso(self, client, user, sp_client):
        request_id, params = authn_request_query(sp_client)
        client.force_login(user)
        content = client.get(reverse("saml:sso"), params).content.decode()
        return sp_client.parse_authn_request_response(
            form_field(content, "SAMLResponse"), BINDING_HTTP_POST, outstanding={request_id: "/"}
        )

    def test_successful_sso_writes_link(self, client):
        user = UserFactory()
        sp = register_sp()
        before = timezone.now()
        self._run_sso(client, user, build_sp_client(client))

        link = UserSamlServiceProviderLink.objects.get()
        assert link.user == user
        assert link.saml_sp == sp
        assert link.last_login >= before

    def test_repeat_sso_updates_last_login_without_duplicating(self, client):
        user = UserFactory()
        register_sp()
        sp_client = build_sp_client(client)

        self._run_sso(client, user, sp_client)
        link = UserSamlServiceProviderLink.objects.get()
        stale = timezone.now() - datetime.timedelta(days=1)
        UserSamlServiceProviderLink.objects.update(last_login=stale)

        self._run_sso(client, user, build_sp_client(client))

        assert UserSamlServiceProviderLink.objects.count() == 1
        link.refresh_from_db()
        assert link.last_login > stale

    def test_no_link_written_without_assertion(self, client):
        user = UserFactory()
        _, params = authn_request_query(build_sp_client(client))
        client.force_login(user)
        assert client.get(reverse("saml:sso"), params).status_code == 400
        assert UserSamlServiceProviderLink.objects.count() == 0


class TestErrorHandling:
    """Slice 11: every invalid/untrusted request renders a clear local error page, is logged in the
    structured `inclusion_connect.saml` format, and is never reflected back to an SP's ACS."""

    ERROR_MARKER = "Connexion impossible"

    def _assert_error_page(self, response, status=400):
        assert response.status_code == status
        assert response["Content-Type"].startswith("text/html")
        content = response.content.decode()
        assert self.ERROR_MARKER in content
        assert "SAMLResponse" not in content
        assert SP_ACS_URL not in content
        return content

    def _saml_logs(self, caplog):
        return [r.msg for r in caplog.records if r.name == "inclusion_connect.saml"]

    def test_unknown_sp_renders_error_page_and_logs(self, client, caplog):
        user = UserFactory()
        _, params = authn_request_query(build_sp_client(client))  # issuer not registered
        client.force_login(user)
        caplog.clear()
        self._assert_error_page(client.get(reverse("saml:sso"), params))
        assert {
            "event": "sso_request_error",
            "error": "unknown_sp",
            "service_provider": SP_ENTITY_ID,
            "ip_address": "127.0.0.1",
        } in self._saml_logs(caplog)

    @pytest.mark.parametrize(
        "params,reason",
        [
            pytest.param({}, "missing_request", id="missing"),
            pytest.param({"SAMLRequest": "not-a-real-saml-request"}, "invalid_request", id="malformed"),
        ],
    )
    def test_invalid_sso_request_renders_error_page_and_logs(self, client, caplog, params, reason):
        register_sp()
        client.force_login(UserFactory())
        caplog.clear()
        self._assert_error_page(client.get(reverse("saml:sso"), params))
        assert any(
            log.get("event") == "sso_request_error" and log.get("error") == reason for log in self._saml_logs(caplog)
        )

    def test_slo_unknown_sp_renders_error_page(self, client):
        user = UserFactory()
        _, params = logout_request(build_sp_client(client), str(user.username))
        client.force_login(user)
        self._assert_error_page(client.get(reverse("saml:slo"), params))

    def test_redirect_to_login_is_logged(self, client, caplog):
        register_sp()
        _, params = authn_request_query(build_sp_client(client))
        caplog.clear()
        response = client.get(reverse("saml:sso"), params)
        login_url = reverse("accounts:login")
        assert response.status_code == 302
        assert response.url.startswith(login_url)
        assert {
            "event": "redirect",
            "service_provider": SP_ENTITY_ID,
            "user": None,
            "url": login_url,
            "ip_address": "127.0.0.1",
        } in self._saml_logs(caplog)


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
