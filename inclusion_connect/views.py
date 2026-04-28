from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.views.decorators.http import require_safe


def csrf_failure(request, template_name="403_csrf.html", **kwargs):
    return render(request, template_name, status=403)


def home(request, template_name="homepage.html", **kwargs):
    return render(request, template_name)


@require_safe
def security_txt(request):
    return HttpResponseRedirect("https://inclusion.beta.gouv.fr/.well-known/security.txt")
