from django.contrib.auth import views as auth_views

from inclusion_connect.www.login.forms import LoginForm


class LoginView(auth_views.LoginView):
    form_class = LoginForm
    template_name = "login.html"

    def get_success_url(self):
        return self.request.session["next_url"]

    def dispatch(self, request, *args, **kwargs):
        next_url = request.GET.get("next")
        if next_url:
            request.session["next_url"] = next_url
            request.session.modified = True
        return super().dispatch(request, *args, **kwargs)
