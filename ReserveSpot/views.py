from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.template import loader
from django.contrib.auth import authenticate, login
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from .forms import LoginForm, RegisterForm, ProfileForm, PaymentForm, OTPVerificationForm, EditProfileForm, ReviewForm, \
    ReservationForm, BookingForm
from .tokens import token_generator
from django.utils import timezone
import json

import datetime
from django.middleware.csrf import get_token

from ReserveSpot.models import Restaurants, Bookings, Payments, Users, MagicLinkTokens, TwoFactorAuthentication, \
    LoginAttempts, Reviews
from .utils import send_otp, generate_magic_link_token, send_magic_link, log_login_attempt, get_location, \
    send_email_verification


# Create your views here.
def home_view(request):
    return render(request, 'home.html')


def members(request):
    return render(request,'home.html')


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)

        if user is not None:
            ip_address = request.META.get('REMOTE_ADDR')
            device = request.META.get('HTTP_USER_AGENT', 'unknown device')
            location = get_location(ip_address)

            last_login_attempt = LoginAttempts.objects.filter(user=user).order_by('-timestamp').first()

            if last_login_attempt:
                last_ip = last_login_attempt.ip_address
                last_device = last_login_attempt.device
            else:
                last_ip = last_device = None

            if last_ip == ip_address and 'Singapore' in location:
                # Low risk: Magic link
                token = generate_magic_link_token(user)
                send_magic_link(user, token, request)
                log_login_attempt(user.id, ip_address, device, location, 'low')
                messages.success(request, 'A magic login link has been sent to your email.')
                return redirect('login_view')
            elif last_device == device:
                # Medium risk: Password
                if user.is_active:
                    request.session.cycle_key()
                    login(request, user)
                    log_login_attempt(user.id, ip_address, device, location, 'medium')
                    messages.success(request, 'Login successful.')
                    return redirect('profile')
                else:
                    messages.error(request, 'Account is inactive.')
                    return redirect('login_view')
            else:
                # High risk: Password + OTP
                send_otp(user)
                request.session['pre_auth_user'] = user.user_id
                log_login_attempt(user.id, ip_address, device, location, 'high')
                messages.success(request, 'OTP has been sent to your email.')
                return redirect('otp_verification_view')

        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'home.html', {'login_form': LoginForm()})


def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['uname']
            email = form.cleaned_data['email']
            password = form.cleaned_data['psw']

            # Create and save user to the database
            user = Users.objects.create(
                username=username,
                email=email,
                password_hash=make_password(password)
            )

            # Send email verification
            send_email_verification(request, user)

            return redirect('profile')  # Redirect to profile page after successful registration
    else:
        form = RegisterForm()

    return render(request, 'home.html', {'register_form': form})


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = Users.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Users.DoesNotExist):
        user = None

    if user is not None and token_generator.check_token(user, token):
        user.is_email_verified = True
        user.save()
        messages.success(request, 'Your email has been verified.')
        return redirect('login_view')
    else:
        messages.error(request, 'The activation link is invalid.')
        return redirect('home_view')


def send_otp_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = Users.objects.get(email=email)
            send_otp(user)
            request.session['pre_auth_user'] = user.user_id
            messages.success(request, 'OTP has been sent to your email.')
            return redirect('otp_verification')
        except Users.DoesNotExist:
            messages.error(request, 'User with this email does not exist.')
            return redirect('send_otp')
    return render(request, 'send_otp.html')


def otp_verification_view(request):
    if request.method == 'POST':
        form = OTPVerificationForm(request.POST)
        if form.is_valid():
            otp = form.cleaned_data['otp']
            user_id = request.session.get('pre_auth_user')
            if not user_id:
                messages.error(request, 'Session expired or invalid.')
                return redirect('login_view')

            try:
                user = Users.objects.get(user_id=user_id)
                two_factor_auth = TwoFactorAuthentication.objects.filter(user=user, number_2fa_method='Email').order_by('-created_at').first()
                if two_factor_auth and two_factor_auth.number_2fa_status == otp and (timezone.now() - two_factor_auth.created_at).total_seconds() < 600:
                    request.session.cycle_key()
                    login(request, user)
                    two_factor_auth.delete()  # Remove OTP after successful verification
                    del request.session['pre_auth_user']  # Remove pre_auth_user from session
                    messages.success(request, 'OTP verified successfully.')
                    return redirect('profile')
                else:
                    messages.error(request, 'Invalid or expired OTP.')
            except Users.DoesNotExist:
                messages.error(request, 'Invalid user.')
        else:
            messages.error(request, 'Form is not valid. Please correct the errors.')
    else:
        form = OTPVerificationForm()

    return render(request, 'otp_verification.html', {'form': form})


def send_magic_link_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = Users.objects.get(email=email)
            token = generate_magic_link_token(user)
            send_magic_link(user, token, request)
            messages.success(request, 'A magic login link has been sent to your email.')
        except Users.DoesNotExist:
            messages.error(request, 'User with this email does not exist.')
    return render(request, 'send_magic_link.html')


def magic_link_verify_view(request, token):
    try:
        magic_link_token = MagicLinkTokens.objects.get(token=token, is_used=False)
        if (timezone.now() - magic_link_token.created_at).total_seconds() > 3600:
            # If the token is older than 1 hour, consider it expired
            magic_link_token.is_used = True
            magic_link_token.save()
            messages.error(request, 'The magic link has expired.')
            return render(request, 'magic_link_verification_failure.html')
        user = magic_link_token.user
        request.session.cycle_key()
        login(request, user)
        magic_link_token.is_used = True
        magic_link_token.save()
        messages.success(request, 'Login successful.')
        return render(request, 'magic_link_verification_success.html')
    except MagicLinkTokens.DoesNotExist:
        messages.error(request, 'Invalid magic link.')
        return render(request, 'magic_link_verification_failure.html')


@login_required
def profile_view(request):
    user = request.user
    user_profile = Users.objects.get(username=user.username)
    user_reviews = Reviews.objects.filter(user_id=user_profile.user_id).order_by('-created_at')[:5]
    return render(request, 'profile.html', {
        'user_profile': user_profile,
        'user_reviews': user_reviews,
    })


def about(request):
    return render(request,'about.html')


@login_required
def edit_profile_view(request):
    user_profile = Users.objects.get(username=request.user.username)

    if request.method == 'POST':
        form = EditProfileForm(request.POST, instance=user_profile)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully.')
            return redirect('profile')
    else:
        form = EditProfileForm(instance=user_profile)

    return render(request, 'editprofile.html', {
        'form': form,
        'user_profile': user_profile
    })


def reservation(request):
    user = request.user

    upcoming_reservations = Bookings.objects.filter(user=user, booking_date__gte=timezone.now())
    past_reservations = Bookings.objects.filter(user=user, booking_date__lt=timezone.now())

    if request.method == 'POST':
        form = ReservationForm(request.POST)
        if form.is_valid():
            reservation = form.save(commit=False)
            reservation.user = user
            reservation.save()
            return redirect('reservations_view')
    else:
        form = ReservationForm()

    context = {
        'upcoming_reservations': upcoming_reservations,
        'past_reservations': past_reservations,
        'form': form,
    }
    return render(request, 'reservation.html', context)


@login_required
def cancel_reservation_view(request, booking_id):
    booking = get_object_or_404(Bookings, pk=booking_id)
    if request.method == 'POST':
        booking.delete()
        messages.success(request, 'Reservation canceled successfully.')
        return redirect('reservations')
    return render(request, 'cancel_reservation.html', {'booking': booking})


@login_required
def edit_reservation_view(request, booking_id):
    booking = get_object_or_404(Bookings, pk=booking_id)
    if request.method == 'POST':
        form = BookingForm(request.POST, instance=booking)
        if form.is_valid():
            form.save()
            messages.success(request, 'Reservation updated successfully.')
            return redirect('reservations')
    else:
        form = BookingForm(instance=booking)
    return render(request, 'edit_reservation.html', {'form': form, 'booking': booking})


@login_required
def payment_view(request, booking_id):
    booking = get_object_or_404(Bookings, pk=booking_id, user=request.user)
    if request.method == 'POST':
        payment_method = request.POST.get('payment_method')
        # Update the database with the payment details
        Payments.objects.create(
            booking=booking,
            payment_method=payment_method,
            amount=booking.total_price,
            status='Pending',
            transaction_date=timezone.now()
        )
        # Redirect to the payment gateway based on selected method
        if payment_method == 'visa':
            return redirect('https://visa-api-url.com')  # Replace with actual Visa API URL
        elif payment_method == 'mastercard':
            return redirect('https://mastercard-api-url.com')  # Replace with actual MasterCard API URL
        elif payment_method == 'googlepay':
            return redirect('https://googlepay-api-url.com')  # Replace with actual Google Pay API URL
        else:
            return redirect('home_view')  # Fallback in case no valid payment method is selected
    else:
        return render(request, 'payment.html', {'booking': booking})


@csrf_exempt
def payment_webhook(request):
    if request.method == 'POST':
        # Parse the incoming notification data
        data = json.loads(request.body)

        # Extract relevant information (this will depend on the payment gateway's payload structure)
        payment_id = data.get('payment_id')
        status = data.get('status')

        # Find the payment record in the database
        try:
            payment = Payments.objects.get(id=payment_id)
            if status == 'approved':
                payment.status = 'Approved'
            else:
                payment.status = 'Failed'
            payment.save()
            return JsonResponse({'status': 'success'})
        except Payments.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Payment not found'}, status=404)
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@login_required
def submit_review_view(request, booking_id):
    try:
        booking = Bookings.objects.get(booking_id=booking_id, user=request.user)
    except Bookings.DoesNotExist:
        messages.error(request, 'Booking not found or you do not have permission to review this booking.')
        return redirect('profile')

    if request.method == 'POST':
        form = ReviewForm(request.POST)
        if form.is_valid():
            review = form.save(commit=False)
            review.user_id = request.user.id
            review.save()
            messages.success(request, 'Review submitted successfully.')
            return redirect('profile')
    else:
        form = ReviewForm(initial={'booking_id': booking_id})

    return render(request, 'submit_review.html', {'form': form, 'booking': booking})


def search_results(request):
    query = request.GET.get('q')
    restaurant_type = request.GET.get('type')
    date = request.GET.get('date')
    price = request.GET.get('price')

    results = Restaurants.objects.all()

    if query:
        results = results.filter(name__icontains=query)

    if restaurant_type:
        results = results.filter(cuisine__icontains=restaurant_type)

    if price:
        results = results.filter(price__icontains=price)

    context = {
        'results': results,
        'query': query,
        'restaurant_type': restaurant_type,
        'date': date,
        'price': price
    }

    return render(request, 'search_results.html', context)


def vendor_listings(request):
    return render(request, 'vendor_listings.html')


def vendor_reservations(request):
    return render(request, 'vendor_reservations.html')


def vendor_transactions(request):
    return render(request, 'vendor_transactions.html')


def restaurant_list(request, cuisine=None):
    if cuisine:
        restaurants = Restaurants.objects.filter(cuisine=cuisine)
    else:
        restaurants = Restaurants.objects.all()

    context = {
        'restaurants': restaurants,
        'cuisine': cuisine,
    }
    return render(request, 'restaurant_list.html', context)
