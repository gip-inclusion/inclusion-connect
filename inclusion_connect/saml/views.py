from dataclasses import dataclass

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import timezone
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
from inclusion_connect.saml.models import SamlServiceProvider, UserSamlServiceProviderLink


LOGGER_NAME = "inclusion_connect.saml"

SAML_SESSION_KEY = "saml_request"


def _base_url(request):
    return request.build_absolute_uri("/").rstrip("/")


def saml_error_response(request, status=400):
    return render(request, "saml_error.html", status=status)


@dataclass(frozen=True)
class InboundRequest:
    saml_request: str
    relay_state: str | None
    binding: str
    sigalg: str | None = None
    signature: str | None = None

    @classmethod
    def from_source(cls, source, binding):
        # RelayState defaults to None (not "") when absent: it is part of the signed octet string.
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
    def get(self, request, *args, **kwargs):
        base_url = _base_url(request)
        config = build_idp_config(base_url)
        metadata = str(entity_descriptor(config))
        log(LOGGER_NAME, request, event="metadata")
        return HttpResponse(
            f'<?xml version="1.0" encoding="UTF-8"?>\n{metadata}',
            content_type="application/samlmetadata+xml",
        )


class _BaseSsoView(View):
    def _dispatch(self, request, inbound):
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
            # Not whitelisted in post_login_actions, so the TOTP / weak / temporary-password gates
            # run before any assertion is issued.
            request.session[SAML_SESSION_KEY] = inbound.to_session()
            request.session["next_url"] = reverse("saml:sso_continue")
            login_url = reverse("accounts:login")
            log(LOGGER_NAME, request, event="redirect", service_provider=sp.entity_id, user=None, url=login_url)
            return HttpResponseRedirect(login_url)

        return self._issue_assertion(request, sp, inbound)

    def _request_error(self, request, reason, **extra):
        log(LOGGER_NAME, request, event="sso_request_error", error=reason, **extra)
        return saml_error_response(request)

    def _issue_assertion(self, request, sp, inbound):
        base_url = _base_url(request)
        try:
            server, message = verify_authn_request(
                base_url, sp.metadata, inbound, sp.require_signed_authn_request, sp.released_attributes()
            )
            acs_url = server.metadata.assertion_consumer_service(sp.entity_id, BINDING_HTTP_POST)[0]["location"]
        except IncorrectlySigned:
            return self._request_error(request, "invalid_signature", service_provider=sp.entity_id)
        except Exception as exc:
            return self._request_error(
                request, "invalid_request", service_provider=sp.entity_id, detail=type(exc).__name__
            )

        user = request.user
        response = server.create_authn_response(
            sp.identity_for(user),
            in_response_to=message.id,
            destination=acs_url,
            sp_entity_id=sp.entity_id,
            name_id=sp.name_id_for(user),
            authn=AUTHN_CONTEXT,
            sign_assertion=sp.sign_assertion,
            sign_response=False,
            # Decide off the parsed metadata: asked to encrypt with no cert, pysaml2 cancels
            # encryption *and* drops the assertion signature, yielding an unsigned one.
            encrypt_assertion=server.has_encrypt_cert_in_metadata(sp.entity_id),
        )
        # On a signing failure pysaml2 returns the error split into a list of lines, not a Response.
        if isinstance(response, list):
            log(LOGGER_NAME, request, event="sso_assertion_error", service_provider=sp.entity_id, user=user.email)
            return saml_error_response(request, status=500)

        http_args = server.apply_binding(
            BINDING_HTTP_POST, str(response), destination=acs_url, relay_state=inbound.relay_state, response=True
        )

        UserSamlServiceProviderLink.objects.update_or_create(
            user=user, saml_sp=sp, defaults={"last_login": timezone.now()}
        )

        log(LOGGER_NAME, request, event="sso_assertion", service_provider=sp.entity_id, user=user.email)
        return HttpResponse(http_args["data"])


@method_decorator(csrf_exempt, name="dispatch")
class SsoView(_BaseSsoView):
    # CSRF-exempt: the AuthnRequest is auto-submitted cross-site by the SP and carries no Django
    # token; authenticity is governed by the SAML layer (issuer lookup + per-SP signature policy).
    def get(self, request, *args, **kwargs):
        return self._dispatch_from(request, request.GET, BINDING_HTTP_REDIRECT)

    def post(self, request, *args, **kwargs):
        return self._dispatch_from(request, request.POST, BINDING_HTTP_POST)

    def _dispatch_from(self, request, source, binding):
        if not source.get("SAMLRequest"):
            return self._request_error(request, "missing_request")
        return self._dispatch(request, InboundRequest.from_source(source, binding))


class ContinueSsoView(_BaseSsoView):
    def get(self, request, *args, **kwargs):
        stashed = request.session.pop(SAML_SESSION_KEY, None)
        if not stashed:
            return self._request_error(request, "missing_request")
        return self._dispatch(request, InboundRequest.from_session(stashed))


@method_decorator(csrf_exempt, name="dispatch")
class SloView(View):
    # Local Single Logout: end every IC session of the user and return a LogoutResponse. No
    # propagation to other SPs. CSRF-exempt for the same reason as SsoView.
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
        base_url = _base_url(request)
        # Build the response before terminating anything, so a delivery/binding failure cannot leave
        # a half-terminated session.
        try:
            server, message = verify_logout_request(base_url, sp.metadata, inbound, sp.require_signed_authn_request)
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
        except IncorrectlySigned:
            return self._request_error(request, "invalid_signature", service_provider=sp.entity_id)
        except Exception as exc:
            return self._request_error(
                request, "invalid_request", service_provider=sp.entity_id, detail=type(exc).__name__
            )

        # Only terminate the session when the request's Subject is the logged-in user: the endpoint is
        # CSRF-exempt and accepts unsigned requests, so a forged LogoutRequest would otherwise force-
        # log-out an arbitrary user. A non-matching request still gets a valid LogoutResponse.
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
        return message.name_id is not None and message.name_id.text == sp.name_id_for(user).text

    def _request_error(self, request, reason, **extra):
        log(LOGGER_NAME, request, event="slo_request_error", error=reason, **extra)
        return saml_error_response(request)
