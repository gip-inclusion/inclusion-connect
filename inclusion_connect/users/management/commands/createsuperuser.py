from django.contrib.auth.management.commands import createsuperuser


class Command(createsuperuser.Command):
    def handle(self, *args, **options):
        username_field = self.UserModel.USERNAME_FIELD
        if options[username_field] is None:
            field = self.UserModel._meta.get_field(username_field)
            options[username_field] = field.default()
        super().handle(*args, **options)
