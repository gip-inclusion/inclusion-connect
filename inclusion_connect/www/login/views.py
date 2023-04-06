from socket import IP_TOS

from django.contrib.auth import views as auth_views


class LoginView(auth_views.LoginView):
    def get_success_url(self):
        return self.request.session["next_url"]

    def dispatch(self, request, *args, **kwargs):
        next_url = request.GET.get("next")
        if next_url:
            request.session["next_url"] = next_url
            request.session.modified = True
        return super().dispatch(request, *args, **kwargs)


# It would be great to allow wildcards in redirect_uris...
# override function ?
