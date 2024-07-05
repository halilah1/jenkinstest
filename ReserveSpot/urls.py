from django.urls import path
from . import views
from .views import payment_webhook, payment_view, otp_verification_view, send_otp_view, activate, edit_profile_view, \
    submit_review_view, edit_reservation_view, cancel_reservation_view, reservation

urlpatterns = [
    path('', views.home_view, name='home'),
    path('members/', views.members, name='members'),
    path('about/', views.about, name='about'),
    path('profile/', views.profile_view, name='profile'),
    path('edit_profile/', edit_profile_view, name='edit_profile'),
    path('reservation/', views.reservation, name='reservation'),
    path('reserveForm/', reservation, name='reserveForm'),
    path('payment/<int:booking_id>/', payment_view, name='payment'),
    path('restaurants/', views.restaurant_list, name='restaurant_list'),
    path('restaurants/<str:cuisine>/', views.restaurant_list, name='restaurant_list_by_cuisine'),
    path('searchResults/', views.search_results, name='searchResults'),
    path('vendorListings/', views.vendor_listings, name='vendorListings'),
    path('vendorReservations/', views.vendor_reservations, name='vendorReservations'),
    path('vendorTransactions/', views.vendor_transactions, name='vendorTransactions'),
    path('login/', views.login_view, name='login_view'),
    path('register/', views.register_view, name='register_view'),
    path('activate/<uidb64>/<token>/', activate, name='activate'),
    path('profileProcess/', views.profile_view, name='profile_view'),
    path('payment-webhook/', payment_webhook, name='payment_webhook'),
    path('otp-verification/', otp_verification_view, name='otp_verification'),
    path('send-otp/', send_otp_view, name='send_otp'),
    path('send-magic-link/', views.send_magic_link_view, name='send_magic_link'),
    path('verify-magic-link/<str:token>/', views.magic_link_verify_view, name='verify_magic_link'),
    path('submit_review/<int:booking_id>/', submit_review_view, name='submit_review'),
    path('edit-reservation/<int:booking_id>/', edit_reservation_view, name='edit_reservation'),
    path('cancel-reservation/<int:booking_id>/', cancel_reservation_view, name='cancel_reservation'),
]