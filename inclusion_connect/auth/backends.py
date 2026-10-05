from django.contrib.auth.backends import ModelBackend

from inclusion_connect.users.models import User


class EmailAuthenticationBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        # Admin form sends a username
        auth_str = email or kwargs.get("username")
        if auth_str is None:
            return

        if not email.endswith("@inclusion.gouv.fr"):
            return  # Only allow our own domain
        # Keep
        update_data = {field: value for field, value in kwargs.items() if value}
        update_data["is_active"] = True
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
