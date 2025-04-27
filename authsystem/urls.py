from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('qr/', views.generate_qr, name='generate_qr'),
    # path('verify-totp/', views.verify_totp, name='verify_totp'),
    path('capture-face/', views.capture_face, name='capture_face'),
    path('biometric-login/', views.biometric_login, name='biometric_login'),
]
