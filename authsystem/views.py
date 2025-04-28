import random
import io
import base64
import cv2
import numpy as np
import pyotp
import qrcode
import face_recognition
from datetime import datetime
import requests
import bson

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from .models import CustomUser, Document



def home(request):
    return render(request, 'home.html')


def register(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        security_question = request.POST['security_question']
        security_answer = request.POST['security_answer']
        biometric_method = request.POST.get('biometric_method')

        # Backend email format validation
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Please enter a valid email address (e.g., user@example.com).')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})

        # Check if username already exists
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})

        # Check if email already exists
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})

        # Always require security question and answer
        if not security_question or not security_answer:
            messages.error(request, 'Security question and answer are required.')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})

        # Validate biometric method
        if biometric_method not in ['fingerprint', 'face']:
            messages.error(request, 'Please select a biometric authentication method and complete the capture.')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})

        # Create user with security question and biometric enabled
        user = CustomUser.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        user.security_question = security_question
        user.security_answer = security_answer
        user.biometric_enabled = True
        user.biometric_method = biometric_method
        user.save()

        # Generate and send OTP
        otp = str(random.randint(1000, 9999))
        request.session['otp'] = otp
        request.session['user_id'] = user.id
        request.session['user_email'] = user.email  # Store email as backup
        
        # Send verification email with error handling
        try:
            send_mail(
                'Email Verification',
                f'Your OTP for registration is: {otp}',
                settings.EMAIL_HOST_USER,
                [email],
                fail_silently=False,
            )
            messages.success(request, 'Registration successful! Please verify your email.')
            return redirect('verify_otp')
        except Exception as e:
            # Log the error
            print(f"Email sending failed: {str(e)}")
            # Delete the user if email sending fails
            user.delete()
            messages.error(request, f'Registration failed: Could not send verification email. Error: {str(e)}')
            return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})
        
    return render(request, 'register.html', {'username': '', 'password': '', 'email': '', 'security_answer': ''})


def verify_otp(request):
    if request.method == 'POST':
        otp = request.POST['otp']
        stored_otp = request.session.get('otp')
        user_id = request.session.get('user_id')
        user_email = request.session.get('user_email')  # Get stored email
        
        if user_id and stored_otp and otp == stored_otp:
            try:
                # Use the ID directly without ObjectId conversion
                user = CustomUser.objects.get(id=user_id)
                user.email_verified = True
                user.save()
                
                # Clear session data
                del request.session['otp']
                del request.session['user_id']
                del request.session['user_email']  # Clear stored email
                
                return redirect('auth_status')
            except CustomUser.DoesNotExist:
                messages.error(request, 'Invalid user session. Please try logging in again.')
                return redirect('login')
        else:
            messages.error(request, 'Invalid OTP.')
    
    # Get user email for display
    user_id = request.session.get('user_id')
    user_email = request.session.get('user_email')
    if user_id:
        try:
            # Use the ID directly without ObjectId conversion
            user = CustomUser.objects.get(id=user_id)
            email = user.email
        except CustomUser.DoesNotExist:
            email = user_email  # Fallback to stored email
    else:
        email = user_email  # Fallback to stored email
    
    return render(request, 'verify_otp.html', {'email': email})


def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Store the user ID as a string before login
            user_id_str = str(user.id)
            
            # Login the user
            login(request, user)
            # Reset security question verification for this session
            request.session['security_question_verified'] = False
            # Reset authentication status if re-authentication is needed
            if user.needs_reauthentication():
                user.recaptcha_verified = False
                user.two_factor_enabled = False
                user.biometric_enabled = False
                user.email_verified = False
                user.save()
            # Always require email verification on new login
            if not user.email_verified:
                # Generate new OTP
                otp = str(random.randint(1000, 9999))
                request.session['otp'] = otp
                request.session['user_id'] = user_id_str  # Use the stored string ID
                request.session['user_email'] = user.email  # Store email as backup
                # Send verification email
                send_mail(
                    'Email Verification',
                    f'Your verification code is: {otp}',
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False,
                )
                return redirect('verify_otp')
            return redirect('auth_status')
        else:
            messages.error(request, 'Invalid credentials.')
    return render(request, 'login.html')


def user_logout(request):
    if request.user.is_authenticated:
        user = request.user
        # Reset all authentication status
        user.recaptcha_verified = False
        user.two_factor_enabled = False
        user.biometric_enabled = False
        user.email_verified = False  # Reset email verification
        # Reset security question verification in session
        request.session['security_question_verified'] = False
        user.save()
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

        if totp.verify(otp):
            user.two_factor_enabled = True
            user.save()
            messages.success(request, 'Two-factor authentication enabled successfully!')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

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
    if request.method == 'POST':
        face_image_data = request.POST.get('face_image')
        if face_image_data:
            try:
                header, imgstr = face_image_data.split(';base64,')
                img_bytes = base64.b64decode(imgstr)
                nparr = np.frombuffer(img_bytes, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                face_encodings = face_recognition.face_encodings(img)
                if face_encodings:
                    new_encoding = face_encodings[0]
                    user = request.user
                    if user.face_encoding:
                        stored_encoding = np.frombuffer(user.face_encoding, dtype=np.float64)
                        matches = face_recognition.compare_faces([stored_encoding], new_encoding)
                        if matches[0]:
                            user.biometric_enabled = True
                            user.save()
                            messages.success(request, 'Face verified successfully!')
                            return redirect('dashboard')
                        else:
                            messages.error(request, 'Face not verified, please retry.')
                            return render(request, 'capture_face.html', {'show_retry': True})
                    else:
                        # First time registration: save encoding
                        user.face_encoding = new_encoding.tobytes()
                        user.biometric_enabled = True
                        user.save()
                        messages.success(request, 'Face captured successfully!')
                        return redirect('dashboard')
                else:
                    messages.error(request, 'No face detected. Please try again.')
                    return render(request, 'capture_face.html', {'show_retry': True})
            except Exception as e:
                messages.error(request, f'Error processing image: {e}')
                return render(request, 'capture_face.html', {'show_retry': True})
        else:
            messages.error(request, 'No image data received.')
            return render(request, 'capture_face.html', {'show_retry': True})
    return render(request, 'capture_face.html')


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
    user = request.user
    if request.method == 'POST' and request.FILES.get('document'):
        uploaded_file = request.FILES['document']
        doc = Document.objects.create(
            user=user,
            file=uploaded_file,
            original_name=uploaded_file.name
        )
        messages.success(request, f'File "{uploaded_file.name}" uploaded successfully!')
        return redirect('dashboard')
    documents = Document.objects.filter(user=user).order_by('-uploaded_at')
    auth_status = {
        'email_verified': user.email_verified,
        'recaptcha_verified': user.recaptcha_verified,
        'security_question_verified': request.session.get('security_question_verified', False),
        'two_factor_enabled': user.two_factor_enabled,
        'biometric_enabled': user.biometric_enabled,
    }
    print('DASHBOARD DEBUG:', auth_status)
    if not all(auth_status.values()):
        from django.contrib.messages import get_messages
        storage = get_messages(request)
        if not any("Please complete all authentication steps" in str(message) for message in storage):
            messages.warning(request, 'Please complete all authentication steps before accessing the dashboard.')
        return redirect('auth_status')
    return render(request, 'dashboard.html', {'user': user, 'documents': documents})

@login_required
def complete_profile(request):
    user = request.user
    if request.method == 'POST':
        # Handle profile picture upload
        if 'profile_picture' in request.FILES:
            user.profile_picture = request.FILES['profile_picture']
        
        # Handle personal details
        try:
            date_of_birth = request.POST.get('date_of_birth')
            if date_of_birth:
                # Ensure the date is in YYYY-MM-DD format
                parsed_date = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
                user.date_of_birth = parsed_date
        except ValueError:
            messages.error(request, 'Invalid date format. Please use YYYY-MM-DD format.')
            return render(request, 'complete_profile.html', {'user': user})
            
        user.phone_number = request.POST.get('phone_number')
        user.address = request.POST.get('address')
        user.bio = request.POST.get('bio')
        
        # Handle ID proof upload
        if 'id_proof' in request.FILES:
            user.id_proof = request.FILES['id_proof']
            user.id_proof_type = request.POST.get('id_proof_type')
        
        user.save()
        
        # Check if 2FA is enabled
        if not user.two_factor_enabled:
            return redirect('generate_qr')
        
        # Check if biometric is enabled
        if not user.biometric_enabled:
            return redirect('capture_face')
        
        messages.success(request, 'Profile completed successfully!')
        return redirect('dashboard')
    
    return render(request, 'complete_profile.html', {'user': user})

@login_required
def check_auth_status(request):
    user = request.user
    # Check if security question is set
    security_question_set = bool(user.security_question and user.security_answer)
    # Check if security question is verified in this session
    security_question_verified = request.session.get('security_question_verified', False)

    auth_status = {
        'email_verified': user.email_verified,
        'recaptcha_verified': user.recaptcha_verified,
        'security_question_set': security_question_set,
        'security_question_verified': security_question_verified if security_question_set else False,
        'two_factor_enabled': user.two_factor_enabled,
        'biometric_enabled': user.biometric_enabled,
    }
    print('AUTH_STATUS DEBUG:', auth_status)
    # Calculate progress percentage (now 6 steps)
    completed_steps = sum(1 for key, status in auth_status.items() if key != 'security_question_set' and status)
    progress_percentage = (completed_steps * 20)  # 5 steps total (excluding 'security_question_set')

    # If all steps are completed, update last_login_time and redirect to dashboard
    if (auth_status['email_verified'] and auth_status['recaptcha_verified'] and
        auth_status['security_question_set'] and auth_status['security_question_verified'] and
        auth_status['two_factor_enabled'] and auth_status['biometric_enabled']):
        user.last_login_time = datetime.now()
        user.save()
        return redirect('dashboard')

    # Determine the next required step
    next_step = None
    if not auth_status['email_verified']:
        next_step = 'email_verification'
    elif not auth_status['recaptcha_verified']:
        next_step = 'recaptcha_verification'
    elif not auth_status['security_question_set']:
        next_step = 'set_security_question'
    elif not auth_status['security_question_verified']:
        next_step = 'verify_security_question'
    elif not auth_status['two_factor_enabled']:
        next_step = 'two_factor_authentication'
    elif not auth_status['biometric_enabled']:
        next_step = 'biometric_authentication'

    return render(request, 'auth_status.html', {
        'auth_status': auth_status,
        'user': user,
        'progress_percentage': progress_percentage,
        'next_step': next_step
    })

@login_required
def verify_recaptcha(request):
    if request.method == 'POST':
        # Get reCAPTCHA response
        recaptcha_response = request.POST.get('g-recaptcha-response')
        
        if recaptcha_response:
            # Verify with Google's reCAPTCHA API
            verify_url = 'https://www.google.com/recaptcha/api/siteverify'
            data = {
                'secret': settings.RECAPTCHA_PRIVATE_KEY,
                'response': recaptcha_response,
                'remoteip': request.META.get('REMOTE_ADDR')
            }
            
            response = requests.post(verify_url, data=data)
            result = response.json()
            
            if result['success']:
                user = request.user
                user.recaptcha_verified = True
                user.save()
                messages.success(request, 'reCAPTCHA verification completed successfully!')
                return redirect('auth_status')
            else:
                messages.error(request, 'reCAPTCHA verification failed. Please try again.')
        else:
            messages.error(request, 'Please complete the reCAPTCHA verification.')
    
    return render(request, 'verify_recaptcha.html')

@login_required
def set_security_question(request):
    if request.method == 'POST':
        # If user already has a security question, verify the answer
        if request.user.security_question and request.user.security_answer:
            answer = request.POST.get('security_answer')
            if answer == request.user.security_answer:
                request.session['security_question_verified'] = True
                messages.success(request, 'Security question verified successfully!')
                return redirect('auth_status')
            else:
                messages.error(request, 'Incorrect answer. Please try again.')
        else:
            # Set new security question
            question = request.POST.get('security_question')
            answer = request.POST.get('security_answer')
            if question and answer:
                user = request.user
                user.security_question = question
                user.security_answer = answer
                user.save()
                request.session['security_question_verified'] = True
                messages.success(request, 'Security question set successfully!')
                return redirect('auth_status')
            else:
                messages.error(request, 'Please provide both question and answer.')
    
    # If user already has a security question, show verification form
    if request.user.security_question:
        return render(request, 'verify_security_question.html', {
            'question': request.user.security_question
        })
    
    # Otherwise show form to set security question
    return render(request, 'set_security_question.html')

@login_required
def check_auth_status_json(request):
    user = request.user
    auth_status = {
        'email_verified': user.email_verified,
        'profile_completed': bool(user.profile_picture and user.date_of_birth and user.phone_number and user.address),
        'id_verified': bool(user.id_proof and user.id_proof_type),
        'two_factor_enabled': user.two_factor_enabled,
        'biometric_enabled': user.biometric_enabled,
    }
    
    return JsonResponse({
        'all_completed': all(auth_status.values()),
        'auth_status': auth_status
    })

@login_required
def resend_verification_email(request):
    user = request.user
    # Generate new OTP
    otp = str(random.randint(1000, 9999))
    request.session['otp'] = otp
    request.session['user_id'] = user.id  # Store ID directly
    request.session['user_email'] = user.email
    
    # Send verification email
    send_mail(
        'Email Verification',
        f'Your verification code is: {otp}',
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )
    
    return redirect('verify_otp')

@login_required
def delete_document(request, doc_id):
    doc = get_object_or_404(Document, id=doc_id, user=request.user)
    if request.method == 'POST':
        doc.file.delete(save=False)  # Delete the file from storage
        doc.delete()
        messages.success(request, 'Document deleted successfully!')
    return redirect('dashboard')


