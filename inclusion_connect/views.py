from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.template import loader
from django.urls import reverse

from inclusion_connect.utils.urls import add_url_params


def csrf_failure(request, template_name="403_csrf.html", **kwargs):
    template = loader.get_template(template_name)
    context = {
        "edit_user_info_url": add_url_params(
            reverse("accounts:edit_user_info"), {"redirect_uri": request.GET.get("referrer_uri")}
        )
    }
    return HttpResponseForbidden(template.render(context))


def home(request, template_name="homepage.html", **kwargs):
    return render(request, template_name)
