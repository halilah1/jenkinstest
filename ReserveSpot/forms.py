from django import forms

from ReserveSpot.models import Bookings, Users, Reviews


class LoginForm(forms.Form):
    uname = forms.CharField(label="uname", max_length=150)
    psw = forms.CharField(label="psw", widget=forms.PasswordInput())


class RegisterForm(forms.Form):
    uname = forms.CharField(label="uname", max_length=150)
    email = forms.EmailField(label="email")
    psw = forms.CharField(label="psw", widget=forms.PasswordInput())


class ProfileForm(forms.Form):
    nameinfo = forms.CharField(label="nameinfo", max_length=150)
    emailinfo = forms.EmailField(label="emailinfo")
    phoneinfo = forms.CharField(label="phoneinfo", max_length=8)
    pwdinfo = forms.CharField(label="pwdinfo", widget=forms.PasswordInput())


class PaymentForm(forms.Form):
    PAYMENT_CHOICES = [
        ('visa', 'Visa'),
        ('mastercard', 'MasterCard'),
        ('googlepay', 'Google Pay')
    ]

    payment_method = forms.ChoiceField(
        choices=PAYMENT_CHOICES,
        widget=forms.RadioSelect,
        required=True
    )


class ReservationForm(forms.ModelForm):
    class Meta:
        model = Bookings
        fields = ['activity', 'booking_date', 'participants', 'special_requests']
        widgets = {
            'booking_date': forms.DateInput(attrs={'type': 'date'}),
            'participants': forms.NumberInput(),
            'special_requests': forms.Textarea(),
        }


class OTPVerificationForm(forms.Form):
    otp = forms.CharField(max_length=6, required=True, widget=forms.TextInput(attrs={'placeholder': 'Enter OTP'}))


class EditProfileForm(forms.ModelForm):
    class Meta:
        model = Users
        fields = ['username', 'email', 'phone_number', 'password_hash']
        widgets = {
            'password_hash': forms.PasswordInput(),
        }


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Reviews
        fields = ['booking_id', 'rating', 'comment']
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 4, 'cols': 40}),
        }


class BookingForm(forms.ModelForm):
    class Meta:
        model = Bookings
        fields = ['booking_date', 'participants', 'special_requests']
