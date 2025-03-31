# iskonnect/forms.py
from django import forms
from django.contrib.auth.forms import AuthenticationForm, SetPasswordForm
from django.core.exceptions import ValidationError
from .models import StudentUser
from .validators import SignupValidator, LoginValidator, StudentNumberValidator

from pydantic import ValidationError as PydanticValidationError

class PydanticFormMixin:
    def clean(self):
        cleaned_data = super().clean()
        try:
            # Validate data with Pydantic
            validator_data = self.get_validator_data(cleaned_data)
            self.validator_class(**validator_data)
        except PydanticValidationError as e:
            # Convert Pydantic validation errors to Django form errors
            error_dict = e.errors()
            for error in error_dict:
                field = error.get('loc')[0]  # Get the field name
                message = error.get('msg')   # Get the error message
                
                # Add the error to the form
                if field in self.fields:
                    self.add_error(field, message)
                else:
                    self.add_error(None, message)  # Add as a form-wide error
                    
        return cleaned_data

class SignupForm(PydanticFormMixin, forms.ModelForm):
    validator_class = SignupValidator
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    
    class Meta:
        model = StudentUser
        fields = ['student_number', 'first_name', 'last_name', 'pup_webmail', 'password', 'confirm_password']
        
    def get_validator_data(self, cleaned_data):
        # Make sure to handle potentially missing fields
        return {
            'student_number': cleaned_data.get('student_number', ''),
            'first_name': cleaned_data.get('first_name', ''),
            'last_name': cleaned_data.get('last_name', ''),
            'pup_webmail': cleaned_data.get('pup_webmail', ''),
            'password': cleaned_data.get('password', '')
        }
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', "Passwords don't match")
        
        return cleaned_data
    
class LoginForm(PydanticFormMixin, AuthenticationForm):
    validator_class = LoginValidator
    
    def get_validator_data(self, cleaned_data):
        return {
            'student_number': cleaned_data.get('username', ''),
            'password': cleaned_data.get('password', '')
        }

class VerificationCodeForm(forms.Form):
    code = forms.CharField(max_length=6, required=True, 
                           widget=forms.TextInput(attrs={'placeholder': 'Enter verification code'}))

class PasswordResetRequestForm(PydanticFormMixin, forms.Form):
    validator_class = StudentNumberValidator
    student_number = forms.CharField(max_length=20, required=True)
    
    def get_validator_data(self, cleaned_data):
        return {
            'student_number': cleaned_data.get('student_number', '')
        }

class PasswordResetForm(SetPasswordForm):
    def clean_new_password1(self):
        password = self.cleaned_data.get('new_password1')
        if len(password) < 8:
            raise ValidationError("Password must be at least 8 characters long.")
        return password