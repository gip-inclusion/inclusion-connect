from django.contrib.auth.mixins import AccessMixin
from django.forms.models import modelform_factory
from django.http import Http404
from django.views import View
from oauth2_provider.models import get_application_model
from oauth2_provider.views import application as application_views


class ApplicationOwnersOnlyMixin(AccessMixin):
    """Verify that the current user is authenticated and has a oidc application."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.oidc_overrides_application.exists():
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)


class ApplicationRegistration(ApplicationOwnersOnlyMixin, View):
    """
    Don't allow to register a new Application for the request.user
    """

    def dispatch(self, request, *args, **kwargs):
        raise Http404()


class ApplicationDetail(ApplicationOwnersOnlyMixin, application_views.ApplicationDetail):
    """
    Detail view for an application instance owned by the request.user
    """

    template_name = "oauth2_provider/application_detail.html"


class ApplicationList(ApplicationOwnersOnlyMixin, application_views.ApplicationList):
    """
    List view for all the applications owned by the request.user
    """

    template_name = "oauth2_provider/application_list.html"


class ApplicationDelete(ApplicationOwnersOnlyMixin, application_views.ApplicationDelete):
    """
    Don't allow to delete an application
    """

    def dispatch(self, request, *args, **kwargs):
        raise Http404()


class ApplicationUpdate(ApplicationOwnersOnlyMixin, application_views.ApplicationUpdate):
    """
    View used to update an application owned by the request.user
    """

    template_name = "oauth2_provider/application_form.html"

    def get_form_class(self):
        """
        Returns the form class for the application model
        """
        return modelform_factory(
            get_application_model(),
            fields=(
                "client_secret",
                "redirect_uris",
                "post_logout_redirect_uris",
            ),
        )
