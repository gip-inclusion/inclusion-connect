from django.contrib.auth.backends import ModelBackend

from inclusion_connect.users.models import User


class EmailAuthenticationBackend(ModelBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        if email is None:
            return
        try:
            # TODO: beware of email case (maybe override user model)
            # TODO: how do we handle login after the user asked to change his email,
            # but before he varified the new one ?
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (see django implmentation)
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
