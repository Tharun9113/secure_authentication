from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Test SendGrid email sending functionality'

    def add_arguments(self, parser):
        parser.add_argument('email', type=str, help='Email address to send test email to')

    def handle(self, *args, **options):
        email = options['email']
        
        # Log email settings (without API key)
        self.stdout.write(f"Email settings: BACKEND={settings.EMAIL_BACKEND}, FROM={settings.DEFAULT_FROM_EMAIL}")
        
        # Test sending email
        self.stdout.write(f"Attempting to send email to {email}...")
        try:
            send_mail(
                'Test Email from SecureAuth (SendGrid)',
                'This is a test email to verify SendGrid email sending functionality.',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS(f'Successfully sent test email to {email}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to send email: {str(e)}'))
            logger.exception("Email sending error") 