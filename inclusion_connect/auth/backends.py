from django.contrib.auth.backends import ModelBackend

from inclusion_connect.users.models import User


class EmailAuthenticationBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        # Admin form sends a username
        auth_str = email or kwargs.get("username")
        if auth_str is None:
            return
        try:
            user = User.objects.get(email__iexact=auth_str)
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (see django implmentation)
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
