import os
import random
import requests

from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from .models import TwoFactorAuthentication, MagicLinkTokens, LoginAttempts
from .tokens import token_generator
import uuid


def generate_otp():
    return random.randint(100000, 999999)


def send_otp(user):
    otp = generate_otp()
    TwoFactorAuthentication.objects.create(
        user=user,
        number_2fa_method='email',
        otp=otp,
        number_2fa_status='enabled',
        created_at=timezone.now()
    )
    mail_subject = 'OTP for ReserveSpot Login'
    message = f'Your One-Time Password (OTP) is: {otp}'
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.send()


def generate_magic_link_token(user):
    token = str(uuid.uuid4())
    MagicLinkTokens.objects.create(
        user=user,
        token=token,
        created_at=timezone.now(),
        is_used=False
    )
    return token


def send_magic_link(user, token, request):
    current_site = get_current_site(request)
    mail_subject = 'Magic Login Link for ReserveSpot'
    protocol = 'https' if request.is_secure() else 'http'
    message = render_to_string('send_magic_link.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': token,
        'protocol': protocol,
    })
    email = EmailMessage(mail_subject, message, to=[user.email])
    email.send()


def log_login_attempt(user_id, ip_address, device, location, risk_level):
    LoginAttempts.objects.create(
        user_id=user_id,
        ip_address=ip_address,
        device=device,
        location=location,
        risk_level=risk_level,
    )


def get_location(ip_address):
    access_key = os.getenv("IPSTACK_API_KEY")
    try:
        response = requests.get(f"http://api.ipstack.com/{ip_address}?access_key={access_key}")
        response.raise_for_status()
        data = response.json()
        country = data.get("country_name", "Unknown")
        return country
    except requests.RequestException:
        return "Unknown"


def send_email_verification(request, user):
    current_site = get_current_site(request)
    mail_subject = 'Activate your ReserveSpot Account.'
    protocol = 'https' if request.is_secure() else 'http'
    message = render_to_string('acc_active_email.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': token_generator.make_token(user),
        'protocol': protocol,
    })
    email = EmailMultiAlternatives(mail_subject, message, to=[user.email])
    email.attach_alternative(message, "text/html")
    email.send()