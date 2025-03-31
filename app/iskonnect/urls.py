from django.urls import path
from django.contrib.auth.views import LogoutView
from .views.auth_views import (
    SignupView, VerifyEmailView, ResendVerificationView, LoginView,
    PasswordResetRequestView, PasswordResetConfirmView, HomeView
)
from django.contrib.auth.decorators import login_required

urlpatterns = [
    # Home page (dashboard) requires authentication
    path('home/', login_required(HomeView.as_view()), name='home'),
    
    # Make login the landing page
    path('', LoginView.as_view(), name='landing'),
    
    # Authentication URLs
    path('login/', LoginView.as_view(), name='login'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify_email'),
    path('resend-verification/', ResendVerificationView.as_view(), name='resend_verification'),
    path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('password-reset/verify/', VerifyEmailView.as_view(), name='password_reset_verify'),
    path('password-reset/confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]