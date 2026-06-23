from django.http import HttpResponse, HttpResponseBadRequest, HttpResponseRedirect, HttpResponseServerError
from django.urls import reverse
from django.views import View
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.metadata import entity_descriptor

from inclusion_connect.logging import log
from inclusion_connect.saml.conf import AUTHN_CONTEXT, build_idp_config, build_idp_server, extract_issuer
from inclusion_connect.saml.models import SamlServiceProvider


LOGGER_NAME = "inclusion_connect.saml"

# Session key holding a validated AuthnRequest awaiting authentication, so the SSO flow can
# resume after login. Kept separate from the OIDC session key — the two protocols never share
# an in-flight request.
SAML_SESSION_KEY = "saml_request"


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

    def _dispatch(self, request, saml_request, relay_state, binding):
        # Read the issuer cheaply (no Server / no xmlsec) just to find the SP; the SP's own server
        # re-parses and validates the request authoritatively before we issue anything.
        try:
            issuer = extract_issuer(saml_request)
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
            # Stash the validated request and resume after login. The continue URL is NOT
            # whitelisted in `post_login_actions`, so the mandatory TOTP / weak-password /
            # temporary-password gates run before any assertion is issued.
            request.session[SAML_SESSION_KEY] = {
                "SAMLRequest": saml_request,
                "RelayState": relay_state,
                "binding": binding,
            }
            # The whole app routes post-login resumption through session ``next_url`` (see
            # OIDCSessionMixin / get_next_url), so set it directly rather than via a ?next= param.
            request.session["next_url"] = reverse("saml:sso_continue")
            return HttpResponseRedirect(reverse("accounts:login"))

        return self._issue_assertion(request, sp, saml_request, relay_state, binding)

    def _request_error(self, request, reason, **extra):
        log(LOGGER_NAME, request, event="sso_request_error", error=reason, **extra)
        return HttpResponseBadRequest("Requête SAML invalide.")

    def _issue_assertion(self, request, sp, saml_request, relay_state, binding):
        base_url = request.build_absolute_uri("/").rstrip("/")
        server = build_idp_server(base_url, sp.metadata)
        # Authoritative parse against the SP's metadata (Destination/structure). pysaml2 raises a
        # wide range of errors on malformed/expired/replayed input — never 500 or reflect them.
        try:
            message = server.parse_authn_request(saml_request, binding).message
        except Exception:
            return self._request_error(request, "invalid_request", service_provider=sp.entity_id)

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
        )
        # On a signing failure (e.g. xmlsec1 missing) pysaml2 returns the error response split into
        # a list of lines instead of a Response — refuse to POST that garbage to the SP.
        if isinstance(response, list):
            log(LOGGER_NAME, request, event="sso_assertion_error", service_provider=sp.entity_id, user=user.email)
            return HttpResponseServerError("Échec de génération de l'assertion SAML.")

        http_args = server.apply_binding(
            BINDING_HTTP_POST, str(response), destination=acs_url, relay_state=relay_state, response=True
        )

        log(LOGGER_NAME, request, event="sso_assertion", service_provider=sp.entity_id, user=user.email)
        return HttpResponse(http_args["data"])


class SsoView(_BaseSsoView):
    """Entry point for an SP-initiated AuthnRequest on the inbound HTTP-Redirect binding."""

    def get(self, request, *args, **kwargs):
        saml_request = request.GET.get("SAMLRequest")
        if not saml_request:
            return self._request_error(request, "missing_request")
        relay_state = request.GET.get("RelayState", "")
        return self._dispatch(request, saml_request, relay_state, BINDING_HTTP_REDIRECT)


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
        return self._dispatch(request, stashed["SAMLRequest"], stashed["RelayState"], stashed["binding"])
