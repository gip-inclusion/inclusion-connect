from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from saml2.mdstore import InMemoryMetaData
from saml2.saml import NAME_FORMAT_URI, NAMEID_FORMAT_EMAILADDRESS, NAMEID_FORMAT_PERSISTENT, NameID

from inclusion_connect.saml.conf import ATTRIBUTE_URIS, default_attribute_policy


def _metadata_store(xml):
    """Parse SP metadata XML into a pysaml2 ``InMemoryMetaData`` store (the same parser an SP
    uses to consume metadata). Single parse path shared by every metadata reader on the model."""
    mds = InMemoryMetaData(None, None)
    mds.parse(xml.encode())
    return mds


def parse_sp_metadata(xml):
    """Parse an SP's SAML metadata, returning ``(entity_id, acs_endpoints)``.

    Uses the same pysaml2 parser an SP would use to consume metadata, so a blob that
    parses here is one the SSO flow can later load. Raises ``ValidationError`` with an
    admin-friendly message for anything malformed or missing the SP bits we rely on.
    """
    if not xml or not xml.strip():
        raise ValidationError("Les métadonnées SAML sont vides.")
    try:
        mds = _metadata_store(xml)
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
        self._validate_attribute_mapping()

    def _validate_attribute_mapping(self):
        """Reject a malformed ``attribute_mapping`` at the admin boundary rather than letting it
        surface as a confusing failure at assertion time. The mapping is operator-supplied JSON, so
        each key must name a canonical attribute and each value be an optional ``name`` /
        ``name_format`` override object.
        """
        if self.attribute_mapping in (None, {}):
            return
        if not isinstance(self.attribute_mapping, dict):
            raise ValidationError({"attribute_mapping": "Le mapping d'attributs doit être un objet JSON."})
        errors = []
        for key, override in self.attribute_mapping.items():
            if key not in ATTRIBUTE_URIS:
                errors.append(f"Attribut inconnu « {key} ». Attributs disponibles : {', '.join(ATTRIBUTE_URIS)}.")
                continue
            if not isinstance(override, dict):
                errors.append(f"La configuration de « {key} » doit être un objet (name / name_format).")
                continue
            if unknown := set(override) - {"name", "name_format"}:
                errors.append(f"Clés non supportées pour « {key} » : {', '.join(sorted(unknown))}.")
        if errors:
            raise ValidationError({"attribute_mapping": errors})

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

    def encrypts_assertions(self):
        """Whether assertions to this SP are encrypted, decided solely by its metadata.

        An SP that publishes a ``KeyDescriptor use="encryption"`` receives an assertion encrypted
        to that certificate (in addition to the default signature); one that does not receives the
        normal signed cleartext assertion. There is no manual per-SP toggle — the SP's metadata is
        the single source of truth, mirroring pysaml2's ``has_encrypt_cert_in_metadata`` gate that
        the SSO view relies on at issue time.
        """
        return bool(_metadata_store(self.metadata).certs(self.entity_id, "spsso", "encryption"))

    def name_id_for(self, user):
        """Build the SAML NameID for ``user`` according to this SP's configured format.

        Default ``persistent`` carries ``User.username`` (the UUID, identical to the OIDC sub);
        SPs that require it can override to ``emailAddress``.
        """
        value = user.email if self.nameid_format == self.NameIdFormat.EMAIL else str(user.username)
        return NameID(format=self.nameid_format, sp_name_qualifier=self.entity_id, text=value)

    def identity_for(self, user):
        """The canonical source attribute set, by friendly name.

        Mirrors the OIDC claims; SIRET/SIREN are static from settings. The per-SP
        ``released_attributes`` policy selects the subset and the emitted name/NameFormat at
        issue time, so this stays the full superset of values the policy can draw from.
        """
        return {
            "email": user.email,
            "given_name": user.first_name,
            "family_name": user.last_name,
            "uid": str(user.pk),
            "siret": settings.SIRET,
            "siren": settings.SIREN,
        }

    def released_attributes(self):
        """Resolve this SP's release policy into ``(canonical_key, emitted_name, name_format)`` tuples.

        Empty ``attribute_mapping`` = zero-config default: the full canonical set under the standard
        URI/OID names. A non-empty mapping selects the released subset (its keys) and, per attribute,
        overrides the emitted ``name`` and/or ``name_format``; unspecified overrides fall back to the
        URI default. Consumed by ``conf._ReleasePolicyConverter`` when building the assertion.
        """
        if not self.attribute_mapping:
            return default_attribute_policy()
        return [
            (key, override.get("name") or ATTRIBUTE_URIS[key], override.get("name_format") or NAME_FORMAT_URI)
            for key, override in self.attribute_mapping.items()
        ]


class UserSamlServiceProviderLink(models.Model):
    """Audit trail of which SAML SPs a user has signed into, and when.

    Written per successful assertion (update-or-create, refreshing ``last_login``), mirroring the
    OIDC ``UserApplicationLink`` so admins can support/audit SAML logins the same way. Distinct
    from the OIDC link because the relying-party type differs (``SamlServiceProvider`` vs the OIDC
    ``Application``).
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name="utilisateur",
        related_name="linked_saml_service_providers",
        on_delete=models.CASCADE,
    )
    saml_sp = models.ForeignKey(
        SamlServiceProvider,
        verbose_name="service provider SAML",
        related_name="linked_users",
        on_delete=models.CASCADE,
    )
    last_login = models.DateTimeField("dernière connexion", default=timezone.now)

    class Meta:
        verbose_name = "service SAML utilisé"
        verbose_name_plural = "services SAML utilisés"
        unique_together = ("user", "saml_sp")

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.saml_sp}"
