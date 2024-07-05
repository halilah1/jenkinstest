from django.contrib import admin
from .models import (
    Users, Categories, Activities, Bookings, Payments, Vendors, Reviews, Promotions,
    TwoFactorAuthentication, ApiAccess, IntegrationLogs, AuditLogs, LoginAttempts, MagicLinkTokens
)


# Register your models here with custom admin configurations.


@admin.register(Users)
class UsersAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_email_verified', 'is_active', 'created_at', 'last_login')
    search_fields = ('username', 'email')
    list_filter = ('is_active', 'is_email_verified', 'created_at', 'last_login')
    ordering = ('-created_at',)


@admin.register(Categories)
class CategoriesAdmin(admin.ModelAdmin):
    list_display = ('category_id', 'name', 'description')
    search_fields = ('name',)
    ordering = ('name',)


@admin.register(Activities)
class ActivitiesAdmin(admin.ModelAdmin):
    list_display = ('activity_id', 'title', 'category', 'description', 'price', 'created_at')
    search_fields = ('name', 'category__name')
    list_filter = ('category', 'created_at')
    ordering = ('-created_at',)


@admin.register(Bookings)
class BookingsAdmin(admin.ModelAdmin):
    list_display = ('booking_id', 'user', 'activity', 'booking_date', 'booking_status', 'participants', 'total_price')
    search_fields = ('user__username', 'activity__name', 'booking_status')
    list_filter = ('booking_status', 'booking_date')
    ordering = ('-booking_date',)


@admin.register(Payments)
class PaymentsAdmin(admin.ModelAdmin):
    list_display = ('payment_id', 'booking', 'payment_method', 'amount', 'status', 'transaction_date')
    search_fields = ('booking__user__username', 'payment_method', 'status')
    list_filter = ('status', 'transaction_date')
    ordering = ('-transaction_date',)


@admin.register(Vendors)
class VendorsAdmin(admin.ModelAdmin):
    list_display = ('vendor_id', 'name', 'contact_info', 'description', 'ratings')
    search_fields = ('name', 'ratings')
    list_filter = ('ratings', 'name')
    ordering = ('ratings',)


@admin.register(Reviews)
class ReviewsAdmin(admin.ModelAdmin):
    list_display = ('review_id', 'booking_id', 'user_id', 'rating', 'created_at')
    search_fields = ('user_id__username', 'booking_id__activity__name')
    list_filter = ('rating', 'created_at')
    ordering = ('-created_at',)


@admin.register(Promotions)
class PromotionsAdmin(admin.ModelAdmin):
    list_display = ('promotion_id', 'description', 'discount_percentage', 'start_date', 'end_date', 'activity')
    search_fields = ('name',)
    list_filter = ('start_date', 'end_date')
    ordering = ('-start_date',)


@admin.register(TwoFactorAuthentication)
class TwoFactorAuthenticationAdmin(admin.ModelAdmin):
    list_display = ('number_2fa_id', 'user', 'number_2fa_method', 'number_2fa_status', 'created_at')
    search_fields = ('user__username', 'number_2fa_method', 'number_2fa_status')
    list_filter = ('number_2fa_status', 'created_at')
    ordering = ('-created_at',)


@admin.register(ApiAccess)
class ApiAccessAdmin(admin.ModelAdmin):
    list_display = ('api_key_id', 'user_id', 'api_key', 'created_at')
    search_fields = ('user__username', 'access_token')
    ordering = ('-created_at',)


@admin.register(IntegrationLogs)
class IntegrationLogsAdmin(admin.ModelAdmin):
    list_display = ('integration_log_id', 'api_key', 'timestamp')
    ordering = ('-timestamp',)


@admin.register(AuditLogs)
class AuditLogsAdmin(admin.ModelAdmin):
    list_display = ('log_id', 'user_id', 'action', 'description', 'ip_address', 'timestamp')
    search_fields = ('user__username', 'action', 'ip_address')
    list_filter = ('timestamp',)
    ordering = ('-timestamp',)


@admin.register(LoginAttempts)
class LoginAttemptsAdmin(admin.ModelAdmin):
    list_display = ('attempt_id', 'user_id', 'ip_address', 'timestamp', 'device', 'location', 'risk_level')
    search_fields = ('user__username', 'ip_address')
    ordering = ('-timestamp',)


@admin.register(MagicLinkTokens)
class MagicLinkTokensAdmin(admin.ModelAdmin):
    list_display = ('token_id', 'user', 'token', 'created_at', 'is_used')
    search_fields = ('user__username', 'token')
    list_filter = ('is_used', 'created_at')
    ordering = ('-created_at',)
