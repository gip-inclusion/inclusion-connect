import logging
import uuid
from functools import partial

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.db import transaction
from django.http import Http404, HttpResponseForbidden, HttpResponseNotFound, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils import http, timezone
from django.utils.html import format_html
from django.views.generic import CreateView, FormView, TemplateView, UpdateView, View

from inclusion_connect.accounts import emails, forms
from inclusion_connect.accounts.helpers import login
from inclusion_connect.logging import log_data
from inclusion_connect.oidc_overrides.models import Application
from inclusion_connect.oidc_overrides.views import OIDCSessionMixin
from inclusion_connect.stats import helpers as stats_helpers
from inclusion_connect.stats.models import Actions
from inclusion_connect.users.models import EmailAddress, User
from inclusion_connect.utils.oidc import get_next_url, initial_from_login_hint, oidc_params


logger = logging.getLogger("inclusion_connect.auth")


EMAIL_CONFIRM_KEY = "email_to_confirm"


class LoginView(OIDCSessionMixin, auth_views.LoginView):
    form_class = forms.LoginForm
    template_name = "login.html"
    EVENT_NAME = "login"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["log"] = log_data(self.request)
        return kwargs

    def form_invalid(self, form):
        log = form.log
        log["event"] = f"{self.EVENT_NAME}_error"
        log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))
        return super().form_invalid(form)

    def form_valid(self, form):
        response = super().form_valid(form)
        log = form.log
        log["event"] = self.EVENT_NAME
        if "application" not in log:
            if application := stats_helpers.get_application(self.request, self.get_success_url()):
                log["application"] = application.client_id
        transaction.on_commit(partial(logger.info, log))
        stats_helpers.account_action(form.get_user(), Actions.LOGIN, self.request, self.get_success_url())
        return response


class BaseUserCreationView(OIDCSessionMixin, CreateView):
    form_class = forms.RegisterForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["log"] = log_data(self.request)
        kwargs["request"] = self.request
        return kwargs

    def get_success_url(self):
        return reverse("accounts:confirm-email")

    def form_invalid(self, form):
        response = super().form_invalid(form)
        log = form.log
        log["event"] = f"{self.EVENT_NAME}_error"
        log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))
        return response

    def form_valid(self, form):
        response = super().form_valid(form)
        email = form.cleaned_data["email"]
        email_address = EmailAddress.objects.get(email=email)
        emails.send_verification_email(self.request, email_address)
        self.request.session[EMAIL_CONFIRM_KEY] = email
        if next_url := self.request.session.get("next_url"):
            self.object.save_next_redirect_uri(next_url)
        form.log["event"] = self.EVENT_NAME
        transaction.on_commit(partial(logger.info, form.log))
        stats_helpers.account_action(form.instance, Actions.REGISTER, self.request)
        return response


class RegisterView(BaseUserCreationView):
    template_name = "register.html"
    EVENT_NAME = "register"

    # TODO: Remove keycloak compatibility
    def dispatch(self, request, *args, **kwargs):
        if all(param in oidc_params(request) for param in ["login_hint", "lastname", "firstname"]):
            return HttpResponseRedirect(reverse("accounts:activate"))
        return super().dispatch(request, *args, **kwargs)


class ActivateAccountView(BaseUserCreationView):
    form_class = forms.ActivateAccountForm
    template_name = "activate_account.html"
    EVENT_NAME = "activate"

    def dispatch(self, request, *args, **kwargs):
        # Check user info is provided
        try:
            self.get_user_info()
            params = oidc_params(self.request)
            self.application = Application.objects.get(client_id=params["client_id"])
        except (KeyError, Application.DoesNotExist):
            return render(
                request,
                "oidc_authorize.html",
                {
                    "error": {
                        "error": "invalid_request",
                        "description": "Missing activation parameters",
                    }
                },
                status=400,
            )
        return super().dispatch(request, *args, **kwargs)

    def get_user_info(self):
        params = oidc_params(self.request)
        return {
            "email": params["login_hint"],
            "first_name": params["firstname"],
            "last_name": params["lastname"],
        }

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context | {"application_name": self.application.name} | self.get_user_info()

    def get_initial(self):
        return super().get_initial() | self.get_user_info()


class PasswordResetView(auth_views.PasswordResetView):
    template_name = "password_reset.html"
    subject_template_name = "registration/password_reset_subject.txt"
    email_template_name = "registration/password_reset_body.txt"
    html_email_template_name = "registration/password_reset_body.html"
    form_class = forms.PasswordResetForm
    EVENT_NAME = "forgot_password"

    def get_initial(self):
        initial = super().get_initial()
        initial.update(initial_from_login_hint(self.request))
        return initial

    def get_success_url(self):
        messages.success(
            self.request,
            format_html(
                "Si un compte existe avec cette adresse e-mail, "
                "vous recevrez un e-mail contenant des instructions pour réinitialiser votre mot de passe."
                '<br><a href="{}" class="matomo-event" data-matomo-category="aide" data-matomo-action="clic" '
                "data-matomo-name=\"J'ai besoin d'aide (mdp reset)\">J’ai besoin d’aide</a>",
                settings.FAQ_URL,
            ),
        )
        return reverse("accounts:login")

    def log(self, event_name, email):
        log = log_data(self.request)
        log["event"] = event_name
        try:
            log["user"] = EmailAddress.objects.get(email=email).user_id
        except EmailAddress.DoesNotExist:
            log["email"] = email
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        email = form.cleaned_data.get("email", form.data.get("email", ""))
        self.log(f"{self.EVENT_NAME}_error", email)
        return response

    def form_valid(self, form):
        response = super().form_valid(form)
        self.log(self.EVENT_NAME, form.cleaned_data["email"])
        return response


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    post_reset_login = True
    EVENT_NAME = "reset_password"
    post_reset_login_backend = settings.DEFAULT_AUTH_BACKEND

    def get_success_url(self):
        return get_next_url(self.request)

    def log(self, event_name, form):
        next_url = self.get_success_url()
        log = log_data(self.request, next_url=next_url)
        log["event"] = event_name
        log["user"] = self.request.user.pk
        if form.errors:
            log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        self.log(f"{self.EVENT_NAME}_error", form)
        return response

    def form_valid(self, form):
        response = super().form_valid(form)
        self.log(self.EVENT_NAME, form)
        self.log(LoginView.EVENT_NAME, form)  # Also log a login here
        stats_helpers.account_action(form.user, Actions.LOGIN, self.request, self.get_success_url())
        return response


class AcceptTermsView(LoginRequiredMixin, TemplateView):
    template_name = "accept_terms.html"
    EVENT_NAME = "accept_terms"

    def post(self, request, *args, **kwargs):
        request.user.terms_accepted_at = timezone.now()
        request.user.save()
        log = log_data(self.request)
        log["event"] = self.EVENT_NAME
        log["user"] = request.user.pk
        transaction.on_commit(partial(logger.info, log))
        return HttpResponseRedirect(get_next_url(request))


class ConfirmEmailView(TemplateView):
    template_name = "email_confirmation.html"
    EVENT_NAME = "send_verification_email"

    def dispatch(self, request, *args, **kwargs):
        try:
            self.email_address = EmailAddress.objects.get(email=request.session[EMAIL_CONFIRM_KEY], verified_at=None)
        except (KeyError, EmailAddress.DoesNotExist):
            return HttpResponseRedirect(reverse("accounts:edit_user_info") + "?" + self.request.GET.urlencode())
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        messages.success(request, "E-mail de vérification envoyé.")
        emails.send_verification_email(request, self.email_address)
        log = log_data(self.request)
        log["event"] = self.EVENT_NAME
        log["user"] = self.email_address.user_id
        transaction.on_commit(partial(logger.info, log))
        return HttpResponseRedirect(self.request.get_full_path())


def handle_email_confirmation(request, user_id, email):
    log = log_data(request)
    log["email"] = email
    try:
        email_address = EmailAddress.objects.select_related("user").get(user_id=user_id, email=email)
    except EmailAddress.DoesNotExist:
        log["event"] = f"{ConfirmEmailTokenView.EVENT_NAME}_error"
        log["error"] = "email not found"
        transaction.on_commit(partial(logger.info, log))
        return HttpResponseNotFound()
    log["user"] = email_address.user_id
    if email_address.verified_at:
        # Monitored by support team. https://itou-inclusion.slack.com/archives/C052401846P/p1686578574136939
        log["event"] = f"{ConfirmEmailTokenView.EVENT_NAME}_error"
        log["error"] = "already verified"
        transaction.on_commit(partial(logger.info, log))
        messages.info(request, "Cette adresse e-mail est déjà vérifiée.")
        if request.user.is_authenticated:
            url = reverse("accounts:edit_user_info")
        else:
            url = reverse("accounts:login")
        return HttpResponseRedirect(url)
    log["event"] = ConfirmEmailTokenView.EVENT_NAME
    email_address.verify()
    login(request, email_address.user)
    try:
        del request.session[EMAIL_CONFIRM_KEY]
    except KeyError:
        pass
    next_url = get_next_url(request)
    if next_url.startswith(reverse("accounts:edit_user_info")):
        messages.success(request, "Votre adresse e-mail a été mise à jour.")

    application = stats_helpers.get_application(request, next_url)
    if application and "application" not in log:
        log["application"] = application.client_id
    transaction.on_commit(partial(logger.info, log))

    log = log.copy()
    log["event"] = LoginView.EVENT_NAME  # Also log a login here
    transaction.on_commit(partial(logger.info, log))
    stats_helpers.account_action(email_address.user, Actions.LOGIN, request, next_url)
    return HttpResponseRedirect(next_url)


def handle_signature_expired(request, email):
    log = log_data(request)
    log["event"] = f"{ConfirmEmailTokenView.EVENT_NAME}_error"
    log["error"] = "link expired"
    log["email"] = email
    try:
        log["user"] = EmailAddress.objects.get(email=email).user_id
    except EmailAddress.DoesNotExist:
        pass
    # Monitored by support team. https://itou-inclusion.slack.com/archives/C052401846P/p1686578574136939
    transaction.on_commit(partial(logger.info, log))
    request.session[EMAIL_CONFIRM_KEY] = email
    messages.error(request, "Le lien de vérification d’adresse e-mail a expiré.")
    return HttpResponseRedirect(reverse("accounts:confirm-email"))


class ConfirmEmailTokenView(View):
    EVENT_NAME = "confirm_email_address"

    @staticmethod
    def decode_email(encoded_email):
        return http.urlsafe_base64_decode(encoded_email).decode()

    def get(self, request, uidb64, token):
        try:
            uid = uuid.UUID(http.urlsafe_base64_decode(uidb64).decode())
        except (TypeError, ValueError, OverflowError) as e:
            raise Http404 from e
        max_age = 24 * 60 * 60 * settings.EMAIL_LINKS_VALIDITY_DAYS
        signer = TimestampSigner()
        try:
            encoded_email = signer.unsign(token, max_age=max_age)
        except SignatureExpired:
            encoded_email = signer.unsign(token)
            email = self.decode_email(encoded_email)
            return handle_signature_expired(request, email)
        except BadSignature as e:
            raise Http404 from e
        email = self.decode_email(encoded_email)
        return handle_email_confirmation(request, uid, email)


class ChangeTemporaryPassword(LoginRequiredMixin, FormView):
    template_name = "password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    EVENT_NAME = "change_temporary_password"

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.request.user}

    def get_context_data(self, **kwargs):
        return super().get_context_data(**kwargs) | {"validlink": True}

    def get_success_url(self):
        return get_next_url(self.request)

    def log(self, event_name, form):
        log = log_data(self.request)
        log["event"] = event_name
        log["user"] = self.request.user.pk
        if form.errors:
            log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        self.log(f"{self.EVENT_NAME}_error", form)
        return response

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        self.log(self.EVENT_NAME, form)
        return super().form_valid(form)


class MyAccountMixin(LoginRequiredMixin):
    application = None

    def setup(self, request, *args, **kwargs):
        referrer = request.GET.get("referrer")
        self.application = Application.objects.filter(client_id=referrer).first()
        return super().setup(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        edit_user_info_url = reverse("accounts:edit_user_info")
        edit_password_url = reverse("accounts:change_password")

        referrer_uri = self.request.GET.get("referrer_uri")
        return context | {
            "edit_user_info": {
                "url": edit_user_info_url + "?" + self.request.GET.urlencode(),
                "active": False,
            },
            "edit_password": {
                "url": edit_password_url + "?" + self.request.GET.urlencode(),
                "active": False,
            },
            "referrer_uri": self.application and referrer_uri,
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
    EVENT_NAME = "edit_user_info"

    def form_invalid(self, form):
        response = super().form_invalid(form)
        log = log_data(self.request)
        log["event"] = f"{self.EVENT_NAME}_error"
        log["user"] = self.request.user.pk
        if self.application:
            log["application"] = self.application.client_id
        log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))
        return response

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["edit_user_info"]["active"] = True
        return context

    def form_valid(self, form):
        response = super().form_valid(form)
        user = self.object
        email = form.cleaned_data["email"]
        log = log_data(self.request)
        log["event"] = self.EVENT_NAME
        log["user"] = self.request.user.pk
        if self.application:
            log["application"] = self.application.client_id
        for key in form.changed_data:
            log[f"old_{key}"] = form.initial[key]
            log[f"new_{key}"] = form.cleaned_data[key]
        transaction.on_commit(partial(logger.info, log))
        if user.email != email and not form.email_case_changed(user):
            # Do not hit the database again, we have all necessary information.
            email_address = EmailAddress(user=user, email=email)
            emails.send_verification_email(self.request, email_address, registration=False)
            self.request.session[EMAIL_CONFIRM_KEY] = email
            user.save_next_redirect_uri(self.request.get_full_path())
            return HttpResponseRedirect(reverse("accounts:confirm-email") + "?" + self.request.GET.urlencode())
        if form.changed_data:
            messages.success(self.request, "Vos informations personnelles ont été mises à jour.")
        return response

    def post(self, request, *args, **kwargs):
        if self.get_object().federation:
            return HttpResponseForbidden()
        return super().post(request, *args, **kwargs)


class PasswordChangeView(MyAccountMixin, FormView):
    template_name = "change_password.html"
    form_class = forms.PasswordChangeForm
    EVENT_NAME = "change_password"

    def dispatch(self, request, *args, **kwargs):
        if getattr(request.user, "federation", None):
            raise PermissionDenied("Un compte fédéré ne peut pas modifier son mot de passe.")
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        return super().get_form_kwargs() | {"user": self.get_object()}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["edit_password"]["active"] = True
        return context

    def log(self, event_name, form):
        log = log_data(self.request)
        log["event"] = event_name
        log["user"] = self.request.user.pk
        if self.application:
            log["application"] = self.application.client_id
        if form.errors:
            log["errors"] = form.errors.get_json_data()
        transaction.on_commit(partial(logger.info, log))

    def form_invalid(self, form):
        response = super().form_invalid(form)
        self.log(f"{self.EVENT_NAME}_error", form)
        return response

    def form_valid(self, form):
        form.save()
        login(self.request, self.get_object())
        self.log(self.EVENT_NAME, form)
        messages.success(self.request, "Votre mot de passe a été mis à jour.")
        return super().form_valid(form)


class NewEmailAlreadyUsed(LoginRequiredMixin, TemplateView):
    template_name = "new_email_already_used.html"

    def post(self, request, *args, **kwargs):
        request.user.new_email_already_used = None
        request.user.save()
        return HttpResponseRedirect(get_next_url(request))
