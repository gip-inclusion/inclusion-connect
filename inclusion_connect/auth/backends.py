from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import ValidationError

from inclusion_connect.users.models import User


class EmailAuthenticationBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        # Admin form sends a username
        auth_str = email or kwargs.get("username")
        if auth_str is None:
            return

        if settings.DEMO_MODE is True:
            if not email.endswith("@inclusion.gouv.fr"):
                return  # Only allow our own domain
            # Keep
            update_data = {field: value for field, value in kwargs.items() if value}
            create_data = {
                "first_name": update_data.get("first_name", "Dominique"),
                "last_name": update_data.get("last_name", "Dupond"),
            }
            user, _created = User.objects.update_or_create(
                email=email,
                defaults=update_data,
                create_defaults=create_data,
            )
            return user

        try:
            user = User.objects.get(email__iexact=auth_str)
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (see django implmentation)
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                try:
                    password_validation.validate_password(password)
                except ValidationError:
                    user.password_is_too_weak = True
                    user.save(update_fields=["password_is_too_weak"])
                return user
