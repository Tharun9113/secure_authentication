from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import date, datetime
from django.conf import settings

class CustomUser(AbstractUser):
    # Use BigAutoField for better compatibility
    id = models.BigAutoField(primary_key=True)
    email_verified = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=16, blank=True, null=True)
    face_encoding = models.BinaryField(blank=True, null=True)  # For biometrics
    
    # Personal Details
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    date_of_birth = models.DateField(
        null=True, 
        blank=True,
        validators=[
            MinValueValidator(date(1900, 1, 1), message="Date of birth must be after 1900"),
            MaxValueValidator(date(2100, 12, 31), message="Date of birth must be before 2100")
        ]
    )
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    
    # Additional Documents
    id_proof = models.FileField(upload_to='documents/', blank=True, null=True)
    id_proof_type = models.CharField(max_length=50, blank=True, null=True)
    
    # Security Questions
    security_question = models.CharField(max_length=200, blank=True, null=True)
    security_answer = models.CharField(max_length=200, blank=True, null=True)
    
    # Authentication Status
    two_factor_enabled = models.BooleanField(default=False)
    biometric_enabled = models.BooleanField(default=False)
    biometric_method = models.CharField(max_length=20, blank=True, null=True)  # 'fingerprint' or 'face'
    recaptcha_verified = models.BooleanField(default=False)
    last_login_time = models.DateTimeField(null=True, blank=True)
    
    def is_fully_authenticated(self):
        """Check if the user has completed all required authentication steps"""
        if self.two_factor_enabled and not self.recaptcha_verified:
            return False
        if self.biometric_enabled and not self.recaptcha_verified:
            return False
        return True
    
    def needs_reauthentication(self):
        """Check if the user needs to re-authenticate"""
        if not self.last_login_time:
            return True
        # Re-authenticate after 30 minutes of inactivity
        time_diff = datetime.now().timestamp() - self.last_login_time.timestamp()
        return time_diff > 1800  # 30 minutes in seconds

class Document(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='documents')
    file = models.FileField(upload_to='documents/')
    original_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.original_name} ({self.user.username})"

