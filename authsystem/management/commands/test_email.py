from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
import smtplib
import ssl
import logging

# Set up logging
logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test email sending functionality'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='Email address to send test email to')
        parser.add_argument('--debug', action='store_true', help='Enable debug mode')

    def handle(self, *args, **options):
        email = options['email']
        debug = options.get('debug', False)
        
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            self.stdout.write(self.style.WARNING("Debug mode enabled"))
        
        # Log email settings (without password)
        self.stdout.write(f"Email settings: HOST={settings.EMAIL_HOST}, PORT={settings.EMAIL_PORT}, USER={settings.EMAIL_HOST_USER}, USE_TLS={settings.EMAIL_USE_TLS}")
        
        # First test SMTP connection
        self.stdout.write("Testing SMTP connection...")
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
                server.set_debuglevel(1 if debug else 0)
                server.ehlo()
                self.stdout.write("EHLO successful")
                server.starttls(context=context)
                self.stdout.write("STARTTLS successful")
                server.ehlo()
                self.stdout.write("Second EHLO successful")
                server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
                self.stdout.write(self.style.SUCCESS("SMTP connection successful!"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"SMTP connection failed: {str(e)}"))
            logger.exception("SMTP connection error")
            return
        
        # Now test sending email
        self.stdout.write(f"Attempting to send email to {email}...")
        try:
            send_mail(
                'Test Email from SecureAuth',
                'This is a test email to verify email sending functionality.',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS(f'Successfully sent test email to {email}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to send email: {str(e)}'))
            logger.exception("Email sending error") 