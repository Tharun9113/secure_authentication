from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('qr/', views.generate_qr, name='generate_qr'),
    # path('verify-totp/', views.verify_totp, name='verify_totp'),
    path('capture-face/', views.capture_face, name='capture_face'),
    path('biometric-login/', views.biometric_login, name='biometric_login'),
    path('auth-status/', views.check_auth_status, name='auth_status'),
    path('check-auth-status/', views.check_auth_status_json, name='check_auth_status_json'),
    path('resend-verification/', views.resend_verification_email, name='resend_verification_email'),
    path('verify-recaptcha/', views.verify_recaptcha, name='verify_recaptcha'),
    path('set-security-question/', views.set_security_question, name='set_security_question'),
    path('delete-document/<int:doc_id>/', views.delete_document, name='delete_document'),
]
