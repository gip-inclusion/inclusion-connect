import factory
from saml2 import BINDING_HTTP_POST
from saml2.config import SPConfig
from saml2.metadata import entity_descriptor

from inclusion_connect.saml.models import SamlServiceProvider


def build_sp_metadata(entity_id, acs_url):
    """Build SP metadata XML the way a real SP would publish it.

    Generated with pysaml2 so it is a faithful counterparty for the IdP under test;
    no cert is embedded (slice 2 only exercises entityID/ACS parsing) and none is needed,
    so this stays free of the xmlsec1 dependency.
    """
    conf = SPConfig()
    conf.load(
        {
            "entityid": entity_id,
            "service": {
                "sp": {
                    "endpoints": {
                        "assertion_consumer_service": [(acs_url, BINDING_HTTP_POST)],
                    },
                },
            },
        }
    )
    return str(entity_descriptor(conf))


class SamlServiceProviderFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = SamlServiceProvider

    name = factory.Faker("company", locale="fr_FR")
    entity_id = factory.Sequence("https://sp{}.example.com/saml/metadata".format)
    metadata = factory.LazyAttribute(
        lambda sp: build_sp_metadata(sp.entity_id, f"{sp.entity_id.rsplit('/', 1)[0]}/acs")
    )
