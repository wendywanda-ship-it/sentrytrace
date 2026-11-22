from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("authentication", "0006_organizational_role_catalog")]

    operations = [
        migrations.AddField(
            model_name="user",
            name="mfa_method",
            field=models.CharField(
                choices=[("authenticator", "Google Authenticator"), ("email", "Email verification code")],
                default="authenticator",
                max_length=20,
            ),
        ),
    ]
