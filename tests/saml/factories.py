import factory
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

from inclusion_connect.saml.models import SamlServiceProvider


def build_sp_metadata(entity_id, acs_url, slo_url=None, key_file=None, cert_file=None, encryption_cert_file=None):
    """Build SP metadata XML the way a real SP would publish it.

    Generated with pysaml2 so it is a faithful counterparty for the IdP under test. By default
    no cert is embedded and none is needed, so this stays free of the xmlsec1 dependency. Passing
    ``cert_file`` advertises a signing certificate (KeyDescriptor use="signing") and flags the SP
    as signing its AuthnRequests, which is what lets the IdP verify request signatures. Passing
    ``encryption_cert_file`` advertises an encryption certificate (KeyDescriptor use="encryption"),
    which is the metadata signal that drives the IdP to encrypt the assertion to that SP. Passing
    ``slo_url`` advertises a SingleLogoutService endpoint, which is where the IdP sends the
    LogoutResponse for an SP-initiated SLO.
    """
    endpoints = {"assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)]}
    if slo_url:
        endpoints["single_logout_service"] = [
            (slo_url, BINDING_HTTP_REDIRECT),
            (slo_url, BINDING_HTTP_POST),
        ]
    sp = {"endpoints": endpoints}
    conf_dict = {"entityid": entity_id, "service": {"sp": sp}}
    if cert_file:
        sp["authn_requests_signed"] = True
        conf_dict["key_file"] = key_file
        conf_dict["cert_file"] = cert_file
    if encryption_cert_file:
        conf_dict["encryption_keypairs"] = [{"key_file": key_file, "cert_file": encryption_cert_file}]
    conf = SPConfig()
    conf.load(conf_dict)
    return str(entity_descriptor(conf))


class SamlServiceProviderFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SamlServiceProvider

    name = factory.Faker("company", locale="fr_FR")
    entity_id = factory.Sequence("https://sp{}.example.com/saml/metadata".format)
    metadata = factory.LazyAttribute(
        lambda sp: build_sp_metadata(sp.entity_id, f"{sp.entity_id.rsplit('/', 1)[0]}/acs")
    )
