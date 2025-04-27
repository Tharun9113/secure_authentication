import random
import io
import base64
import cv2
import numpy as np
import pyotp
import qrcode
import face_recognition

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.http import HttpResponse
from django.shortcuts import render, redirect

from .models import CustomUser



def home(request):
    return render(request, 'home.html')


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        user = CustomUser.objects.create_user(username=username, email=email, password=password)
        otp = str(random.randint(1000, 9999))
        request.session['otp'] = otp
        request.session['user_id'] = user.id
        send_mail('OTP Verification', f'Your OTP is {otp}', settings.EMAIL_HOST_USER, [email])
        return redirect('verify_otp')
    return render(request, 'register.html')


def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST['otp']
        if entered_otp == request.session.get('otp'):
            user = CustomUser.objects.get(id=request.session['user_id'])
            user.email_verified = True
            user.save()
            messages.success(request, 'Email verified successfully! Please login.')
            return redirect('login')
        else:
            messages.error(request, 'Incorrect OTP. Please try again.')
    return render(request, 'verify_otp.html')


def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None and user.email_verified:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid credentials or Email not verified.')
    return render(request, 'login.html')


def user_logout(request):
    logout(request)
    return redirect('login')

@login_required
def generate_qr(request):
    user = request.user

    if not user.otp_secret:
        user.otp_secret = pyotp.random_base32()
        user.save()

    otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.email, issuer_name="SecureAuth")
    img = qrcode.make(otp_uri)
    buf = io.BytesIO()
    img.save(buf)
    image_stream = buf.getvalue()
    qr_code = base64.b64encode(image_stream).decode('utf-8')

    if request.method == 'POST':
        otp = request.POST.get('otp')
        totp = pyotp.TOTP(user.otp_secret)

        # Verify the OTP entered by the user
        if totp.verify(otp):
            messages.success(request, 'OTP verified successfully!')
            return redirect('dashboard')  # Redirect to the dashboard if OTP is valid
        else:
            messages.error(request, 'Invalid OTP. Please try again.')  # Error message for invalid OTP

    return render(request, 'show_qr.html', {'qr_code': qr_code})

# @login_required
# def generate_qr(request):
#     user = request.user

#     if not user.otp_secret:
#         user.otp_secret = pyotp.random_base32()
#         user.save()

#     otp_uri = pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.email, issuer_name="SecureAuth")
#     img = qrcode.make(otp_uri)
#     buf = io.BytesIO()
#     img.save(buf)
#     image_stream = buf.getvalue()
#     qr_code = base64.b64encode(image_stream).decode('utf-8')

#     # Handle OTP verification in the same view
#     if request.method == 'POST':
#         otp = request.POST.get('otp')
#         if otp:
#             totp = pyotp.TOTP(user.otp_secret)
#             if totp.verify(otp):
#                 messages.success(request, 'OTP verified successfully!')
#             else:
#                 messages.error(request, 'Invalid OTP. Please try again.')
    
#     return render(request, 'show_qr.html', {'qr_code': qr_code})



@login_required
def capture_face(request):
    video = cv2.VideoCapture(0)
    ret, frame = video.read()
    if ret:
        face_encodings = face_recognition.face_encodings(frame)
        if face_encodings:
            user = request.user
            user.face_encoding = face_encodings[0].tobytes()
            user.save()
            messages.success(request, 'Face captured successfully!')
        else:
            messages.error(request, 'No face detected. Please try again.')
    else:
        messages.error(request, 'Failed to access the camera.')

    video.release()
    return redirect('dashboard')


def biometric_login(request):
    video = cv2.VideoCapture(0)

    if not video.isOpened():
        return render(request, 'biometric_login.html', {'error': 'Unable to access camera'})

    ret, frame = video.read()
    if not ret:
        video.release()
        return render(request, 'biometric_login.html', {'error': 'Failed to capture image from camera'})

    face_encodings = face_recognition.face_encodings(frame)

    if not face_encodings:
        video.release()
        return render(request, 'biometric_login.html', {'error': 'No face detected. Please try again.'})

    for user in CustomUser.objects.all():
        if user.face_encoding:
            known_encoding = np.frombuffer(user.face_encoding, dtype=np.float64)
            matches = face_recognition.compare_faces([known_encoding], face_encodings[0])
            if matches[0]:
                login(request, user)
                video.release()
                return redirect('dashboard')

    video.release()
    return render(request, 'biometric_login.html', {'error': 'Face not recognized. Please try again.'})


@login_required
def dashboard(request):
    return render(request, 'dashboard.html')


