from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
import logging

logger = logging.getLogger(__name__)

class SendGridEmailBackend(BaseEmailBackend):
    """
    SendGrid Email Backend
    """
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently)
        self.api_key = getattr(settings, 'SENDGRID_API_KEY', None)
        if not self.api_key:
            logger.warning('SENDGRID_API_KEY is not set in settings.py')
            return
        self.client = SendGridAPIClient(self.api_key)
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None)
        if not self.from_email:
            logger.warning('DEFAULT_FROM_EMAIL is not set in settings.py')

    def send_messages(self, email_messages):
        """
        Send one or more EmailMessage objects and return the number of email
        messages sent.
        """
        if not email_messages:
            return 0

        if not self.api_key or not self.from_email:
            if not self.fail_silently:
                raise ValueError('SENDGRID_API_KEY or DEFAULT_FROM_EMAIL is not set')
            return 0

        num_sent = 0
        for message in email_messages:
            try:
                sent = self._send(message)
                if sent:
                    num_sent += 1
            except Exception as e:
                if not self.fail_silently:
                    raise
                logger.error(f'Failed to send email: {str(e)}')

        return num_sent

    def _send(self, email_message):
        """
        Send an email using SendGrid API
        """
        if not isinstance(email_message, EmailMultiAlternatives):
            email_message = EmailMultiAlternatives(
                subject=email_message.subject,
                body=email_message.body,
                from_email=email_message.from_email or self.from_email,
                to=email_message.to,
                alternatives=[],
            )

        from_email = Email(email_message.from_email or self.from_email)
        to_emails = [To(email) for email in email_message.to]
        
        # Create the message
        message = Mail(
            from_email=from_email,
            to_emails=to_emails,
            subject=email_message.subject,
            plain_text_content=email_message.body,
        )

        # Add HTML content if available
        if hasattr(email_message, 'alternatives') and email_message.alternatives:
            for content, mimetype in email_message.alternatives:
                if mimetype == 'text/html':
                    message.content = Content('text/html', content)
                    break

        # Send the email
        response = self.client.send(message)
        
        # Log the response
        logger.info(f'SendGrid API Response: {response.status_code}')
        
        return response.status_code in [200, 201, 202] 