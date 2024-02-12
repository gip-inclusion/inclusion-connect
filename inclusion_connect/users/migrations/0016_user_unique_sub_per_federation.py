# Generated by Django 4.2.9 on 2024-02-05 16:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0015_rename_must_reset_password_user_password_is_temporary"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="user",
            constraint=models.UniqueConstraint(
                condition=models.Q(("federation", None), _negated=True),
                fields=("federation", "federation_sub"),
                name="unique_sub_per_federation",
                violation_error_message="L’identifiant de fédération (sub) est associé à un autre utilisateur.",
            ),
        ),
    ]