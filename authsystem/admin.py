from django.contrib import admin
from .models import CustomUser  # Import your model

@admin.register(CustomUser)  # Register CustomUser in the admin
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'email_verified')  # Custom fields for display
