from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from saml2.mdstore import InMemoryMetaData
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_PERSISTENT, NameID


def parse_sp_metadata(xml):
    """Parse an SP's SAML metadata, returning ``(entity_id, acs_endpoints)``.

    Uses the same pysaml2 parser an SP would use to consume metadata, so a blob that
    parses here is one the SSO flow can later load. Raises ``ValidationError`` with an
    admin-friendly message for anything malformed or missing the SP bits we rely on.
    """
    if not xml or not xml.strip():
        raise ValidationError("Les métadonnées SAML sont vides.")
    mds = InMemoryMetaData(None, None)
    try:
        mds.parse(xml.encode())
    except Exception as exc:
        raise ValidationError("Métadonnées SAML invalides : le XML n'a pas pu être analysé.") from exc
    entity_ids = list(mds.keys())
    if len(entity_ids) != 1:
        raise ValidationError("Les métadonnées doivent décrire exactement un EntityDescriptor.")
    entity_id = entity_ids[0]
    acs = mds.service(entity_id, "spsso_descriptor", "assertion_consumer_service")
    if not acs:
        raise ValidationError(
            "Les métadonnées ne contiennent pas de SPSSODescriptor avec un AssertionConsumerService."
        )
    return entity_id, acs


class SamlServiceProvider(models.Model):
    """A SAML 2.0 service provider registered against the IC IdP.

    The relying-party identity (entityID, ACS URLs, bindings, signing/encryption certs)
    lives entirely in the pasted ``metadata`` XML — pysaml2 parses it at SSO time. The
    remaining fields are IC-side release/security policy consumed by later slices. This is
    a separate model from the OIDC ``Application``: the two relying-party types share
    almost no fields.
    """

    class NameIdFormat(models.TextChoices):
        PERSISTENT = NAMEID_FORMAT_PERSISTENT, "persistent (UUID, identique au sub OIDC)"
        EMAIL = NAMEID_FORMAT_EMAILADDRESS, "emailAddress"

    name = models.CharField("nom", max_length=255, help_text="Libellé interne du service provider.")
    entity_id = models.CharField("entityID", max_length=255, unique=True, editable=False)
    metadata = models.TextField(
        "métadonnées XML",
        help_text="Coller les métadonnées SAML du service provider. L'entityID et les URLs ACS en sont extraits.",
    )

    attribute_mapping = models.JSONField(
        "mapping d'attributs",
        default=dict,
        blank=True,
        help_text="Sous-ensemble d'attributs publiés et, par attribut, le nom et le NameFormat émis. "
        "Vide = mapping par défaut de l'IdP.",
    )
    nameid_format = models.CharField(
        "format du NameID",
        max_length=256,
        choices=NameIdFormat,
        default=NameIdFormat.PERSISTENT,
    )
    sign_assertion = models.BooleanField("signer l'assertion", default=True)
    encrypt_assertion = models.BooleanField(
        "chiffrer l'assertion",
        default=False,
        help_text="N'a d'effet que si les métadonnées du SP publient un certificat de chiffrement.",
    )
    require_signed_authn_request = models.BooleanField(
        "exiger des AuthnRequest signées",
        default=False,
        help_text="Rejeter les AuthnRequest non signées de ce SP. À activer une fois le SP capable de signer.",
    )

    created_at = models.DateTimeField("créé le", auto_now_add=True)
    updated_at = models.DateTimeField("modifié le", auto_now=True)

    class Meta:
        verbose_name = "service provider SAML"
        verbose_name_plural = "services providers SAML"

    def __str__(self):
        return self.name or self.entity_id

    def clean(self):
        self.entity_id, _ = parse_sp_metadata(self.metadata)
        # `entity_id` is editable=False, so Django excludes it from the admin form's
        # validate_unique(); check the collision here to surface a clean field error
        # rather than an IntegrityError 500 when the same SP metadata is registered twice.
        if SamlServiceProvider.objects.filter(entity_id=self.entity_id).exclude(pk=self.pk).exists():
            raise ValidationError(
                {"metadata": f"Un service provider avec l'entityID « {self.entity_id} » est déjà enregistré."}
            )

    def save(self, *args, **kwargs):
        # Derive entity_id for programmatic creates (factories, data migrations) that skip
        # full_clean. The admin path has already set it in clean(), so guard against
        # re-parsing the same blob a second time on every save.
        if not self.entity_id:
            self.entity_id, _ = parse_sp_metadata(self.metadata)
        super().save(*args, **kwargs)

    def acs_endpoints(self):
        """The SP's AssertionConsumerService endpoints parsed from the metadata."""
        _, acs = parse_sp_metadata(self.metadata)
        return [endpoint["location"] for endpoints in acs.values() for endpoint in endpoints]

    def name_id_for(self, user):
        """Build the SAML NameID for ``user`` according to this SP's configured format.

        Default ``persistent`` carries ``User.username`` (the UUID, identical to the OIDC sub);
        SPs that require it can override to ``emailAddress``.
        """
        value = user.email if self.nameid_format == self.NameIdFormat.EMAIL else str(user.username)
        return NameID(format=self.nameid_format, sp_name_qualifier=self.entity_id, text=value)

    def identity_for(self, user):
        """The canonical default attribute set released to this SP, by friendly name.

        Mirrors the OIDC claims; mapped to URI-format names at issue time. SIRET/SIREN are
        static from settings. Per-SP subsetting/renaming via ``attribute_mapping`` is a later slice.
        """
        return {
            "email": user.email,
            "given_name": user.first_name,
            "family_name": user.last_name,
            "uid": str(user.pk),
            "siret": settings.SIRET,
            "siren": settings.SIREN,
        }
