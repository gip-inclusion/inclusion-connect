import uuid

from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import http, timezone
from django.views.generic import CreateView, FormView, TemplateView, UpdateView, View

from inclusion_connect.accounts import emails, forms
from inclusion_connect.accounts.helpers import login
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.urls import add_url_params


EMAIL_CONFIRM_KEY = "email_to_confirm"


class LoginView(OIDCSessionMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"


class BaseUserCreationView(OIDCSessionMixin, CreateView):
    form_class = forms.RegisterForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["request"] = self.request
        return kwargs

    def get_success_url(self):
        return reverse("accounts:confirm-email")

    def form_valid(self, form):
        response = super().form_valid(form)
        email = form.cleaned_data["email"]
        email_address = EmailAddress.objects.get(email=email)
        emails.send_verification_email(self.request, email_address)
        self.request.session[EMAIL_CONFIRM_KEY] = email
        return response


class RegisterView(BaseUserCreationView):
    template_name = "register.html"

    # TODO: Remove keycloak compatibility
    def dispatch(self, request, *args, **kwargs):
        if all(param in self.get_oidc_params() for param in ["login_hint", "lastname", "firstname"]):
            return HttpResponseRedirect(reverse("accounts:activate"))
        return super().dispatch(request, *args, **kwargs)


class ActivateAccountView(BaseUserCreationView):
    form_class = forms.ActivateAccountForm
    template_name = "activate_account.html"

    def dispatch(self, request, *args, **kwargs):
        # Check user info is provided
        try:
            self.get_user_info()
        except KeyError:
            return render(
                request,
                "oidc_authorize.html",
                {"error": {"error": "invalid_request", "description": "Missing activation parameters"}},
                status=400,
            )
        return super().dispatch(request, *args, **kwargs)

    def get_user_info(self):
        params = self.get_oidc_params()

        # TODO: Remove keycloak compatibility
        try:
            return {
                "email": params["login_hint"],
                "first_name": params["firstname"],
                "last_name": params["lastname"],
            }
        except KeyError:
            return {
                "email": params["email"],
                "first_name": params["firstname"],
                "last_name": params["lastname"],
            }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # TODO Get oauth2 application name from client_id
        return context | {"application_name": "Les emplois de l'inclusion"} | self.get_user_info()

    def get_initial(self):
        return super().get_initial() | self.get_user_info()


class PasswordResetView(auth_views.PasswordResetView):
    template_name = "password_reset.html"
    form_class = forms.PasswordResetForm

    def get_success_url(self):
        messages.success(
            self.request,
            "Si un compte existe avec cette adresse e-mail, "
            "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe.",
        )
        return reverse("accounts:login")


class PasswordResetConfirmView(OIDCSessionMixin, auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    post_reset_login = True


class AcceptTermsView(LoginRequiredMixin, OIDCSessionMixin, TemplateView):
    template_name = "accept_terms.html"

    def post(self, *args, **kwargs):
        self.request.user.terms_accepted_at = timezone.now()
        self.request.user.save()
        return HttpResponseRedirect(self.get_success_url())


class ConfirmEmailView(TemplateView):
    template_name = "email_confirmation.html"

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        try:
            self.email_address = EmailAddress.objects.get(email=request.session[EMAIL_CONFIRM_KEY], verified_at=None)
        except (KeyError, EmailAddress.DoesNotExist) as e:
            raise Http404 from e

    def post(self, request):
        messages.success(request, "E-mail de vérification envoyé.")
        emails.send_verification_email(request, self.email_address)
        return HttpResponseRedirect(reverse("accounts:confirm-email"))


class ConfirmEmailTokenView(OIDCSessionMixin, View):
    @staticmethod
    def decode_email(encoded_email):
        return http.urlsafe_base64_decode(encoded_email).decode()

    def get(self, request, uidb64, token):
        try:
            uid = uuid.UUID(http.urlsafe_base64_decode(uidb64).decode())
        except (TypeError, ValueError, OverflowError) as e:
            raise Http404 from e
        one_day = 24 * 60 * 60
        signer = TimestampSigner()
        try:
            encoded_email = signer.unsign(token, max_age=one_day)
        except SignatureExpired:
            encoded_email = signer.unsign(token)
            email = self.decode_email(encoded_email)
            request.session[EMAIL_CONFIRM_KEY] = email
            messages.error(request, "Le lien de vérification d’adresse e-mail a expiré.")
            return HttpResponseRedirect(reverse("accounts:confirm-email"))
        except BadSignature as e:
            raise Http404 from e
        # Signature matched, the payload is valid.
        email = self.decode_email(encoded_email)
        email_address = get_object_or_404(EmailAddress.objects.select_related("user"), email=email, user_id=uid)
        if email_address.verified_at:
            messages.info(request, "Cette adresse e-mail est déjà vérifiée.")
            if request.user.is_authenticated:
                url = reverse("accounts:edit_user_info")
            else:
                url = reverse("accounts:login")
            return HttpResponseRedirect(url)
        email_address.verify()
        login(request, email_address.user)
        try:
            del request.session[EMAIL_CONFIRM_KEY]
        except KeyError:
            pass
        return HttpResponseRedirect(self.get_success_url())


class ChangeTemporaryPassword(LoginRequiredMixin, OIDCSessionMixin, FormView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.request.user}

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"validlink": True}

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        return super().form_valid(form)


class MyAccountMixin(LoginRequiredMixin):
    # FIXME: Also handle referrer params as in keycloak
    # - we can display the application name in the return button: "Retour vers Dora"
    #   but it may be too long in some cases
    # - we can log that the user came from the given application

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        referrer_uri = self.request.GET.get("referrer_uri")
        return context | {
            "edit_user_info_url": add_url_params(reverse("accounts:edit_user_info"), {"referrer_uri": referrer_uri}),
            "edit_password_url": add_url_params(reverse("accounts:change_password"), {"referrer_uri": referrer_uri}),
            "referrer_uri": referrer_uri,
        }

    def get_object(self, queryset=None):
        return self.request.user

    def get_success_url(self):
        # Stay on page
        return self.request.get_full_path()


class EditUserInfoView(MyAccountMixin, UpdateView):
    template_name = "edit_user_info.html"
    form_class = forms.EditUserInfoForm
    model = User

    # FIXME Add a message on success to tell the user to click on return if he's done ?
    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object
        email = form.cleaned_data["email"]
        if user.email != email:
            # Do not hit the database again, we have all necessary information.
            email_address = EmailAddress(user=user, email=email)
            emails.send_verification_email(self.request, email_address)
            self.request.session[EMAIL_CONFIRM_KEY] = email
            return HttpResponseRedirect(reverse("accounts:confirm-email"))
        return response


class PasswordChangeView(MyAccountMixin, FormView):
    template_name = "change_password.html"
    form_class = forms.PasswordChangeForm

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.get_object()}

    def form_valid(self, form):
        form.save()
        login(self.request, self.get_object())
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        return super().form_valid(form)
