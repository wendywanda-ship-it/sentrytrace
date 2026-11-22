from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
import pyotp


class Command(BaseCommand):
    help = "Print the current TOTP code for a demo account."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **options):
        user = get_user_model().objects.filter(username=options["username"]).first()
        if not user or not user.totp_secret:
            raise CommandError("User was not found or has no configured TOTP secret.")
        self.stdout.write(pyotp.TOTP(user.totp_secret).now())
