from oauth2_provider.oauth2_backends import OAuthLibCore


# FIXME: remove once handled in django-oauth-toolkit
class CustomOAuthLibCore(OAuthLibCore):
    def extract_headers(self, request):
        headers = super().extract_headers(request)
        if "HTTP_ORIGIN" in headers:
            headers["Origin"] = headers["HTTP_ORIGIN"]
        return headers
