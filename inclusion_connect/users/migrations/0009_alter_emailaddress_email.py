import django.contrib.postgres.fields.citext
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0008_user_next_redirect_uri_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="emailaddress",
            name="email",
            field=django.contrib.postgres.fields.citext.CIEmailField(
                max_length=254, unique=True, verbose_name="adresse e-mail"
            ),
        ),
    ]
