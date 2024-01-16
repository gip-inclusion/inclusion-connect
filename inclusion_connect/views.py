from django.shortcuts import render
from django.urls import reverse
from django.views.decorators.http import require_safe

from inclusion_connect.utils.urls import add_url_params


def csrf_failure(request, template_name="403_csrf.html", **kwargs):
    context = {
        "edit_user_info_url": add_url_params(
            reverse("accounts:edit_user_info"), {"redirect_uri": request.GET.get("referrer_uri")}
        )
    }
    return render(request, template_name, context=context, status=403)


def home(request, template_name="homepage.html", **kwargs):
    return render(request, template_name)


def accessibility(request, template_name="accessibility.html", **kwargs):
    return render(request, template_name)


@require_safe
def security_txt(request, template_name="security.txt", **kwargs):
    # https://www.rfc-editor.org/rfc/rfc9116
    # https://securitytxt.org/ can be helpful in generating the document.
    return render(
        request,
        template_name,
        content_type="text/plain; charset=utf-8",
    )
