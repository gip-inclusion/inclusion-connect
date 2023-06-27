from django.contrib.admin import forms as admin_forms, sites as admin_sites

from inclusion_connect.users.models import User


class AdminAuthenticationForm(admin_forms.AdminAuthenticationForm):
    def __init__(self, request=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].widget.attrs["maxlength"] = User._meta.get_field("email").max_length
        self.fields["username"].label = "Adresse e-mail"


class AdminSite(admin_sites.AdminSite):
    login_form = AdminAuthenticationForm
