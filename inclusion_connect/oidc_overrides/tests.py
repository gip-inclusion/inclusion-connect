from inclusion_connect.oidc_overrides.factories import ApplicationFactory


def test_allow_wildcard_in_redirect_uris():
    application = ApplicationFactory(redirect_uris="http://localhost/*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    application = ApplicationFactory(redirect_uris="*")
    assert application.redirect_uri_allowed("http://localhost/callback")

    # We do not handle wildcard in domains
    application = ApplicationFactory(redirect_uris="http://*.mydomain.com/callback")
    assert not application.redirect_uri_allowed("http://site1.mydomain.com/callback")
