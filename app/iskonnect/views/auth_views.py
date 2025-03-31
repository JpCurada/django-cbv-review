# iskonnect/views/auth_views.py
from django.views.generic import CreateView, FormView, TemplateView
from django.contrib.auth.views import LoginView as BaseLoginView
from django.contrib.auth.views import PasswordResetConfirmView
from django.contrib import messages
from django.shortcuts import redirect, get_object_or_404
from django.urls import reverse_lazy
from django.utils import timezone
from django.views import View

from ..models import StudentUser, VerificationCode
from ..forms import (
    SignupForm, LoginForm, VerificationCodeForm, 
    PasswordResetRequestForm, PasswordResetForm
)
from ..utils import send_verification_email

class SignupView(CreateView):
    template_name = 'iskonnect/signup.html'
    form_class = SignupForm
    success_url = reverse_lazy('verify_email')
    
    def form_valid(self, form):
        # Save user but set as inactive until email verification
        user = form.save(commit=False)
        user.is_active = False
        user.set_password(form.cleaned_data['password'])
        user.save()
        
        # Send verification email
        send_verification_email(user, 'email_verification')
        
        # Store user_id in session for the verification view
        self.request.session['verification_user_id'] = user.id
        self.request.session['verification_purpose'] = 'email_verification'
        
        messages.success(
            self.request, 
            "Account created! Please check your email for verification code."
        )
        return super().form_valid(form)
    
    def form_invalid(self, form):
        # Add a message for general form errors
        if form.non_field_errors():
            for error in form.non_field_errors():
                messages.error(self.request, error)
        
        return super().form_invalid(form)

class VerifyEmailView(FormView):
    template_name = 'iskonnect/verify_email.html'
    form_class = VerificationCodeForm
    success_url = reverse_lazy('login')
    
    def dispatch(self, request, *args, **kwargs):
        # Check if there's a user to verify
        if 'verification_user_id' not in request.session:
            messages.error(request, "Verification session expired.")
            return redirect('signup')
        return super().dispatch(request, *args, **kwargs)
    
    def form_valid(self, form):
        user_id = self.request.session['verification_user_id']
        purpose = self.request.session.get('verification_purpose', 'email_verification')
        user = get_object_or_404(StudentUser, pk=user_id)
        
        # Get the latest verification code
        try:
            verification = VerificationCode.objects.filter(
                user=user, 
                purpose=purpose
            ).latest('created_at')
            
            if not verification.is_valid():
                messages.error(self.request, "Verification code expired. Please request a new one.")
                return self.form_invalid(form)
            
            if verification.code != form.cleaned_data['code']:
                messages.error(self.request, "Invalid verification code.")
                return self.form_invalid(form)
            
            # Code is valid - verify the email
            if purpose == 'email_verification':
                user.is_active = True
                user.email_verified = True
                user.save()
                messages.success(self.request, "Email verified successfully! You can now log in.")
            elif purpose == 'password_reset':
                # Store in session for password reset confirm
                self.request.session['password_reset_user_id'] = user.id
                self.success_url = reverse_lazy('password_reset_confirm')
                messages.success(self.request, "Code verified! Now you can reset your password.")
            
            # Clean up
            verification.delete()
            if purpose == 'email_verification':
                del self.request.session['verification_user_id']
                del self.request.session['verification_purpose']
            
            return super().form_valid(form)
            
        except VerificationCode.DoesNotExist:
            messages.error(self.request, "No verification code found. Please request a new one.")
            return self.form_invalid(form)
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['purpose'] = self.request.session.get('verification_purpose', 'email_verification')
        return context

class ResendVerificationView(View):
    def get(self, request):
        if 'verification_user_id' not in request.session:
            messages.error(request, "Verification session expired.")
            return redirect('signup')
        
        user_id = request.session['verification_user_id']
        purpose = request.session.get('verification_purpose', 'email_verification')
        user = get_object_or_404(StudentUser, pk=user_id)
        
        # Send a new verification code
        send_verification_email(user, purpose)
        
        messages.success(request, "A new verification code has been sent to your email.")
        if purpose == 'email_verification':
            return redirect('verify_email')
        else:
            return redirect('password_reset_verify')

class LoginView(BaseLoginView):
    template_name = 'iskonnect/login.html'
    form_class = LoginForm
    
    def form_valid(self, form):
        user = form.get_user()
        if not user.email_verified:
            messages.error(self.request, "Please verify your email before logging in.")
            return redirect('signup')
        return super().form_valid(form)
    
    def form_invalid(self, form):
        # Add clearer messages for authentication errors
        messages.error(
            self.request, 
            "Invalid student number or password. Please try again."
        )
        return super().form_invalid(form)

class PasswordResetRequestView(FormView):
    template_name = 'iskonnect/password_reset_request.html'
    form_class = PasswordResetRequestForm
    success_url = reverse_lazy('password_reset_verify')
    
    def form_valid(self, form):
        student_number = form.cleaned_data['student_number']
        
        try:
            user = StudentUser.objects.get(student_number=student_number)
            
            # Send reset verification code
            send_verification_email(user, 'password_reset')
            
            # Store user_id in session for verification
            self.request.session['verification_user_id'] = user.id
            self.request.session['verification_purpose'] = 'password_reset'
            
            messages.success(
                self.request, 
                "Password reset code sent to your email."
            )
            return super().form_valid(form)
            
        except StudentUser.DoesNotExist:
            messages.error(self.request, "No account found with this student number.")
            return self.form_invalid(form)

class PasswordResetConfirmView(FormView):
    template_name = 'iskonnect/password_reset_confirm.html'
    form_class = PasswordResetForm
    success_url = reverse_lazy('login')
    
    def dispatch(self, request, *args, **kwargs):
        if 'password_reset_user_id' not in request.session:
            messages.error(request, "Password reset session expired.")
            return redirect('password_reset')
        
        self.user = get_object_or_404(StudentUser, pk=request.session['password_reset_user_id'])
        return super().dispatch(request, *args, **kwargs)
    
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.user
        return kwargs
    
    def form_valid(self, form):
        form.save()
        
        # Clean up
        del self.request.session['password_reset_user_id']
        if 'verification_user_id' in self.request.session:
            del self.request.session['verification_user_id']
        if 'verification_purpose' in self.request.session:
            del self.request.session['verification_purpose']
        
        messages.success(self.request, "Password has been reset successfully! You can now log in.")
        return super().form_valid(form)
    

class HomeView(TemplateView):
    template_name = 'iskonnect/home.html'