# Generated by Django 4.1.9 on 2023-07-02 16:30

import django.core.serializers.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0010_alter_userapplicationlink_unique_together"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="federation",
            field=models.TextField(
                choices=[("peama", "Pôle emploi")], null=True, verbose_name="Fournisseur d'identité"
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="federation_data",
            field=models.JSONField(
                blank=True,
                encoder=django.core.serializers.json.DjangoJSONEncoder,
                null=True,
                verbose_name="informations complémentaires",
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="federation_sub",
            field=models.TextField(null=True, verbose_name="identifiant (sub)"),
        ),
    ]
