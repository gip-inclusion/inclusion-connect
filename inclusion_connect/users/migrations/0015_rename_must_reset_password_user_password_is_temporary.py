# Generated by Django 4.2.7 on 2023-11-17 09:34

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0014_user_password_too_weak"),
    ]

    operations = [
        migrations.RenameField(
            model_name="user",
            old_name="must_reset_password",
            new_name="password_is_temporary",
        ),
    ]
