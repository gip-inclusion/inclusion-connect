from dataclasses import dataclass

from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, HttpResponseServerError
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.metadata import entity_descriptor
from saml2.response import IncorrectlySigned

from inclusion_connect.accounts.helpers import delete_user_sessions
from inclusion_connect.logging import log
from inclusion_connect.saml.conf import (
    AUTHN_CONTEXT,
    build_idp_config,
    extract_issuer,
    extract_logout_issuer,
    verify_authn_request,
    verify_logout_request,
)
from inclusion_connect.saml.models import SamlServiceProvider


LOGGER_NAME = "inclusion_connect.saml"

# Session key holding a validated AuthnRequest awaiting authentication, so the SSO flow can
# resume after login. Kept separate from the OIDC session key — the two protocols never share
# an in-flight request.
SAML_SESSION_KEY = "saml_request"


@dataclass(frozen=True)
class InboundRequest:
    """An SP-initiated AuthnRequest in transit.

    ``sigalg``/``signature`` carry the Redirect-binding query-string signature; they are None on
    the POST binding, where the signature is enveloped in the SAMLRequest XML. The dataclass keeps
    the message and its out-of-band signature together as one unit across the login detour.
    """

    saml_request: str
    relay_state: str | None
    binding: str
    sigalg: str | None = None
    signature: str | None = None

    @classmethod
    def from_source(cls, source, binding):
        """Build from a request's GET (Redirect) or POST params.

        Redirect-binding signatures ride in the query string (SigAlg/Signature); the POST binding
        carries an enveloped signature inside the XML, so those stay None there. RelayState defaults
        to None (not "") when absent: it is part of the Redirect-binding signed octet string, so an
        injected empty value would break signature verification.
        """
        redirect = binding == BINDING_HTTP_REDIRECT
        return cls(
            saml_request=source["SAMLRequest"],
            relay_state=source.get("RelayState"),
            binding=binding,
            sigalg=source.get("SigAlg") if redirect else None,
            signature=source.get("Signature") if redirect else None,
        )

    @classmethod
    def from_session(cls, stashed):
        return cls(
            stashed["SAMLRequest"],
            stashed["RelayState"],
            stashed["binding"],
            stashed.get("SigAlg"),
            stashed.get("Signature"),
        )

    def to_session(self):
        return {
            "SAMLRequest": self.saml_request,
            "RelayState": self.relay_state,
            "binding": self.binding,
            "SigAlg": self.sigalg,
            "Signature": self.signature,
        }


class MetadataView(View):
    """Serve dynamically generated IdP metadata.

    pysaml2 builds the document from the current config so a signing certificate
    rotation or an endpoint change is always reflected without a manual update.
    """

    def get(self, request, *args, **kwargs):
        base_url = request.build_absolute_uri("/").rstrip("/")
        config = build_idp_config(base_url)
        metadata = str(entity_descriptor(config))
        log(LOGGER_NAME, request, event="metadata")
        return HttpResponse(
            f'<?xml version="1.0" encoding="UTF-8"?>\n{metadata}',
            content_type="application/samlmetadata+xml",
        )


class _BaseSsoView(View):
    """Shared engine for the two SP-initiated SSO entry points.

    ``SsoView`` reads the AuthnRequest from the request; ``ContinueSsoView`` replays it from
    the session after login. Both funnel into ``_dispatch``: validate against a registered SP,
    gate on authentication, and — for an authenticated user — build a signed Response and
    auto-POST it to the SP's ACS. No consent screen (mirrors OIDC ``skip_authorization``);
    privacy is governed by the per-SP attribute-release policy.
    """

    def _dispatch(self, request, inbound):
        # Read the issuer cheaply (no Server / no xmlsec) just to find the SP; the SP's own server
        # re-parses and validates the request authoritatively before we issue anything.
        try:
            issuer = extract_issuer(inbound.saml_request, inbound.binding)
        except Exception:
            issuer = None
        if not issuer:
            return self._request_error(request, "invalid_request")

        sp = SamlServiceProvider.objects.filter(entity_id=issuer).first()
        if sp is None:
            return self._request_error(request, "unknown_sp", service_provider=issuer)

        log(
            LOGGER_NAME,
            request,
            event="sso_request",
            service_provider=sp.entity_id,
            user=request.user.email if request.user.is_authenticated else None,
        )

        if not request.user.is_authenticated:
            # Stash the request (signature params included, so a Redirect-binding signature can be
            # re-verified on resume) and continue after login. The continue URL is NOT whitelisted
            # in `post_login_actions`, so the mandatory TOTP / weak-password / temporary-password
            # gates run before any assertion is issued.
            request.session[SAML_SESSION_KEY] = inbound.to_session()
            # The whole app routes post-login resumption through session ``next_url`` (see
            # OIDCSessionMixin / get_next_url), so set it directly rather than via a ?next= param.
            request.session["next_url"] = reverse("saml:sso_continue")
            return HttpResponseRedirect(reverse("accounts:login"))

        return self._issue_assertion(request, sp, inbound)

    def _request_error(self, request, reason, **extra):
        log(LOGGER_NAME, request, event="sso_request_error", error=reason, **extra)
        return HttpResponseBadRequest("Requête SAML invalide.")

    def _issue_assertion(self, request, sp, inbound):
        base_url = request.build_absolute_uri("/").rstrip("/")
        # Authoritative parse + signature verification against the SP's metadata. pysaml2 raises a
        # wide range of errors on malformed/expired/replayed input — never 500 or reflect them.
        try:
            server, message = verify_authn_request(
                base_url, sp.metadata, inbound, sp.require_signed_authn_request, sp.released_attributes()
            )
        except IncorrectlySigned:
            return self._request_error(request, "invalid_signature", service_provider=sp.entity_id)
        except Exception as exc:
            # Keep the SP-facing message generic but record the cause: SAML interop failures
            # (clock skew, Destination mismatch, schema error…) are otherwise indistinguishable
            # from a hostile request in the logs.
            return self._request_error(
                request, "invalid_request", service_provider=sp.entity_id, detail=type(exc).__name__
            )

        user = request.user
        acs_url = server.metadata.assertion_consumer_service(sp.entity_id, BINDING_HTTP_POST)[0]["location"]
        response = server.create_authn_response(
            sp.identity_for(user),
            in_response_to=message.id,
            destination=acs_url,
            sp_entity_id=sp.entity_id,
            name_id=sp.name_id_for(user),
            authn=AUTHN_CONTEXT,
            sign_assertion=sp.sign_assertion,
            sign_response=False,
            # Decide off the parsed metadata, not pysaml2's own gate: asked to encrypt with no cert,
            # pysaml2 cancels encryption *and* drops the assertion signature, yielding an unsigned one.
            encrypt_assertion=server.has_encrypt_cert_in_metadata(sp.entity_id),
        )
        # On a signing failure (e.g. xmlsec1 missing) pysaml2 returns the error response split into
        # a list of lines instead of a Response — refuse to POST that garbage to the SP.
        if isinstance(response, list):
            log(LOGGER_NAME, request, event="sso_assertion_error", service_provider=sp.entity_id, user=user.email)
            return HttpResponseServerError("Échec de génération de l'assertion SAML.")

        http_args = server.apply_binding(
            BINDING_HTTP_POST, str(response), destination=acs_url, relay_state=inbound.relay_state, response=True
        )

        log(LOGGER_NAME, request, event="sso_assertion", service_provider=sp.entity_id, user=user.email)
        return HttpResponse(http_args["data"])


@method_decorator(csrf_exempt, name="dispatch")
class SsoView(_BaseSsoView):
    """Entry point for an SP-initiated AuthnRequest on either inbound binding.

    HTTP-Redirect arrives as a GET, HTTP-POST as a form POST. The POST path is CSRF-exempt: the
    AuthnRequest is auto-submitted cross-site by the SP and carries no Django CSRF token; its
    authenticity is governed by the SAML layer (issuer lookup + per-SP signature policy), not CSRF.
    """

    def get(self, request, *args, **kwargs):
        return self._dispatch_from(request, request.GET, BINDING_HTTP_REDIRECT)

    def post(self, request, *args, **kwargs):
        return self._dispatch_from(request, request.POST, BINDING_HTTP_POST)

    def _dispatch_from(self, request, source, binding):
        if not source.get("SAMLRequest"):
            return self._request_error(request, "missing_request")
        return self._dispatch(request, InboundRequest.from_source(source, binding))


class ContinueSsoView(_BaseSsoView):
    """Resume an SP-initiated SSO once the user has authenticated.

    The AuthnRequest stashed at login time is replayed from the session. Reaching this view
    means ``post_login_actions`` has already let the request through, i.e. the mandatory TOTP /
    weak-password / temporary-password gates are cleared — only then is an assertion issued.
    """

    def get(self, request, *args, **kwargs):
        stashed = request.session.pop(SAML_SESSION_KEY, None)
        if not stashed:
            return self._request_error(request, "missing_request")
        return self._dispatch(request, InboundRequest.from_session(stashed))


@method_decorator(csrf_exempt, name="dispatch")
class SloView(View):
    """Local Single Logout: terminate the IC session on an SP-initiated LogoutRequest.

    "Local" means we end the user's IC session (every session of theirs, mirroring the OIDC
    RP-initiated logout) and return a ``LogoutResponse`` to the requesting SP — we do NOT
    propagate the logout to any other SP the user is signed in to (deferred). Because the IC
    session is shared with OIDC, this also logs the user out of the OIDC surface, so a later
    SSO attempt requires re-authentication.

    Accepted on both inbound bindings (Redirect = GET, POST = form). CSRF-exempt for the same
    reason as ``SsoView``: the SP auto-submits cross-site without a Django token; authenticity is
    governed by the SAML layer (issuer lookup + per-SP signature policy).
    """

    def get(self, request, *args, **kwargs):
        return self._handle(request, request.GET, BINDING_HTTP_REDIRECT)

    def post(self, request, *args, **kwargs):
        return self._handle(request, request.POST, BINDING_HTTP_POST)

    def _handle(self, request, source, binding):
        if not source.get("SAMLRequest"):
            return self._request_error(request, "missing_request")
        inbound = InboundRequest.from_source(source, binding)

        try:
            issuer = extract_logout_issuer(inbound.saml_request, inbound.binding)
        except Exception:
            issuer = None
        if not issuer:
            return self._request_error(request, "invalid_request")

        sp = SamlServiceProvider.objects.filter(entity_id=issuer).first()
        if sp is None:
            return self._request_error(request, "unknown_sp", service_provider=issuer)

        user = request.user if request.user.is_authenticated else None
        log(
            LOGGER_NAME,
            request,
            event="slo_request",
            service_provider=sp.entity_id,
            user=user.email if user else None,
        )
        return self._logout(request, sp, inbound, user)

    def _logout(self, request, sp, inbound, user):
        base_url = request.build_absolute_uri("/").rstrip("/")
        try:
            server, message = verify_logout_request(
                base_url, sp.metadata, inbound, sp.require_signed_authn_request
            )
        except IncorrectlySigned:
            return self._request_error(request, "invalid_signature", service_provider=sp.entity_id)
        except Exception as exc:
            return self._request_error(
                request, "invalid_request", service_provider=sp.entity_id, detail=type(exc).__name__
            )

        # Build the response first, so a delivery/binding failure cannot leave a half-terminated
        # session. pick_binding resolves the SP's SLS location + binding from its metadata; the
        # response is unsigned, mirroring the SSO path's unsigned Response (sign_response=False).
        rinfo = server.response_args(message, [inbound.binding])
        response = server.create_logout_response(message, [inbound.binding], sign=False)
        http_args = server.apply_binding(
            rinfo["binding"],
            str(response),
            destination=rinfo["destination"],
            relay_state=inbound.relay_state,
            response=True,
            sign=False,
        )

        # Only terminate the session when the request's Subject is the logged-in user. The endpoint
        # is necessarily CSRF-exempt and accepts unsigned requests by default, so without this a
        # forged LogoutRequest (any NameID, any registered SP) carried by the victim's browser would
        # force-log-out an arbitrary user. Requiring a NameID match means the attacker must already
        # know the victim's identifier; combine with per-SP `require_signed_authn_request` for full
        # protection. A non-matching request still gets a valid (Success) LogoutResponse.
        logged_out = user if user is not None and self._targets_user(sp, message, user) else None
        if logged_out is not None:
            delete_user_sessions(logged_out)

        log(
            LOGGER_NAME,
            request,
            event="slo_response",
            service_provider=sp.entity_id,
            user=logged_out.email if logged_out else None,
        )
        if rinfo["binding"] == BINDING_HTTP_REDIRECT:
            return HttpResponseRedirect(dict(http_args["headers"])["Location"])
        return HttpResponse(http_args["data"])

    @staticmethod
    def _targets_user(sp, message, user):
        """Whether the LogoutRequest's Subject NameID identifies ``user`` for this SP."""
        return message.name_id is not None and message.name_id.text == sp.name_id_for(user).text

    def _request_error(self, request, reason, **extra):
        log(LOGGER_NAME, request, event="slo_request_error", error=reason, **extra)
        return HttpResponseBadRequest("Requête SAML invalide.")
