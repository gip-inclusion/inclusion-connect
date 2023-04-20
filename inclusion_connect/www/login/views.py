from django.contrib.auth import authenticate, login, views as auth_views
from django.views.generic import CreateView

from inclusion_connect.www.login.forms import LoginForm, RegistrationForm


class OidcArgumentMixin:
    def get_success_url(self):
        return self.request.session["next_url"]

    def dispatch(self, request, *args, **kwargs):
        next_url = request.GET.get("next")
        if next_url:
            request.session["next_url"] = next_url
            request.session.modified = True
        return super().dispatch(request, *args, **kwargs)


class LoginView(OidcArgumentMixin, auth_views.LoginView):
    form_class = LoginForm
    template_name = "login.html"


class RegistrationView(OidcArgumentMixin, CreateView):
    form_class = RegistrationForm
    template_name = "registration.html"

    def form_valid(self, form):
        result = super().form_valid(form)
        self.user = authenticate(
            email=form.cleaned_data["email"],
            password=form.cleaned_data["password1"],
        )
        login(self.request, self.user)
        return result
