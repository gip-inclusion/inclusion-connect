import re


namespace_pattern = re.compile(r"^keycloak_compat_(?P<realm>.+)$")


def realm_from_request(request):
    namespace = request.resolver_match.namespace
    match = namespace_pattern.match(namespace)
    return match.group("realm")
