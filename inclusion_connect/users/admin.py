import copy
import logging
from functools import partial

from django import forms
from django.contrib import admin
from django.contrib.auth import admin as auth_admin, forms as auth_forms, password_validation
from django.db import transaction

from inclusion_connect.logging import log_data

from .models import User, UserApplicationLink


logger = logging.getLogger("inclusion_connect.auth")


class AdminPasswordChangeForm(forms.Form):
    """
    A form used to change the password of a user in the admin interface.
    """

    required_css_class = "required"
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.TextInput(attrs={"autocomplete": "new-password", "autofocus": True}),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_password(self):
        self.cleaned_data["set_usable_password"] = True
        password = self.cleaned_data.get("password")
        password_validation.validate_password(password, self.user)
        return password

    def save(self, commit=True):
        password = self.cleaned_data["password"]
        self.user.set_password(password)
        self.user.password_is_temporary = True
        if commit:
            self.user.save()
        return self.user

    @property
    def changed_data(self):
        data = super().changed_data
        for name in self.fields:
            if name not in data:
                return []
        return ["password"]


class UserApplicationLinkInline(admin.TabularInline):
    model = UserApplicationLink
    extra = 0
    can_delete = False

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request, obj):
        return False


class TemporaryPasswordWidget(forms.Widget):
    template_name = "admin/widgets/temporary_password.html"


class UserChangeForm(auth_forms.UserChangeForm):
    password = None
    password_is_temporary = forms.Field(
        label="Mot de passe",
        disabled=True,
        required=False,
        widget=TemporaryPasswordWidget,
    )

    def __init__(self, *args, instance, **kwargs):
        super().__init__(*args, instance=instance, **kwargs)
        email = self.fields.get("email")
        if email:
            email.label = "Adresse e-mail vérifiée"

    def log_changes(self, request):
        log = log_data(request)
        log["event"] = "admin_change"
        log["acting_user"] = request.user.pk
        log["user"] = self.instance.pk
        tracked_changed_fields = set(self.changed_data) & {"first_name", "last_name"}
        for field in sorted(tracked_changed_fields):
            log[f"old_{field}"] = self.initial[field]
            log[f"new_{field}"] = self.cleaned_data[field]
        if "groups" in self.changed_data:
            current_groups = set(self.initial["groups"])
            new_groups = set(self.cleaned_data["groups"])
            log["groups"] = {}
            added_groups = new_groups - current_groups
            if added_groups:
                log["groups"]["added"] = {}
                for group in added_groups:
                    log["groups"]["added"][group.pk] = group.name
            removed_groups = current_groups - added_groups
            if removed_groups:
                log["groups"]["removed"] = {}
                for group in current_groups - new_groups:
                    log["groups"]["removed"][group.pk] = group.name
        transaction.on_commit(partial(logger.info, log))


@admin.register(User)
class UserAdmin(auth_admin.UserAdmin):
    model = User
    form = UserChangeForm
    readonly_fields = [
        "username",
        "date_joined",
        "last_login",
    ]
    list_filter = auth_admin.UserAdmin.list_filter + ("password_is_temporary",)
    inlines = [UserApplicationLinkInline]
    change_password_form = AdminPasswordChangeForm
    search_fields = auth_admin.UserAdmin.search_fields
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_staff",
    )

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if change:
            form.log_changes(request)
        else:
            log = log_data(request)
            log["event"] = "admin_add"
            log["acting_user"] = request.user.pk
            log["user"] = form.instance.pk
            transaction.on_commit(partial(logger.info, log))

    def construct_change_message(self, request, form, formsets, add=False):
        """
        Abusing the only method called with the request and user when a change_password succeeded.
        """
        change_message = super().construct_change_message(request, form, formsets, add=add)
        if isinstance(form, self.change_password_form):
            log = log_data(request)
            log["event"] = "admin_change_password"
            log["acting_user"] = request.user.pk
            log["user"] = form.user.pk
            transaction.on_commit(partial(logger.info, log))
        return change_message

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        is_change_form = obj is not None
        if is_change_form:
            fieldsets = list(copy.deepcopy(fieldsets))
            assert fieldsets[0] == (None, {"fields": ("username", "password")})
            if not self.has_change_permission(request, obj):
                fieldsets[0][1]["fields"] = ("username",)
            else:
                fieldsets[0][1]["fields"] = ("username", "password_is_temporary")

            assert fieldsets[1] == ("Informations personnelles", {"fields": ("first_name", "last_name", "email")})

            assert fieldsets[2][0] == "Permissions"
            if request.user.is_superuser:
                if obj and not obj.is_staff:
                    # Hide space-consuming widgets for groups and user_permissions.
                    fieldsets[2] = ("Permissions", {"fields": ["is_active", "is_staff", "is_superuser"]})
            else:
                del fieldsets[2]

        return fieldsets

    def get_readonly_fields(self, request, obj=None):
        rof = super().get_readonly_fields(request, obj)
        if not request.user.is_superuser:
            rof = [*rof, "is_staff", "is_superuser", "groups", "user_permissions"]
        return rof

    def has_change_permission(self, request, obj=None):
        if getattr(obj, "is_superuser", False) and not request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)
