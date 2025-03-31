from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _

class StudentUserManager(BaseUserManager):
    def create_user(self, student_number, pup_webmail, password=None, **extra_fields):
        if not student_number:
            raise ValueError('The Student Number field must be set')
        if not pup_webmail:
            raise ValueError('The PUP Webmail field must be set')
        
        email = self.normalize_email(pup_webmail)
        user = self.model(student_number=student_number, pup_webmail=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, student_number, pup_webmail, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        
        return self.create_user(student_number, pup_webmail, password, **extra_fields)

class StudentUser(AbstractUser):
    username = None  # We'll use student_number instead of username
    student_number = models.CharField(_('student number'), max_length=20, unique=True)
    first_name = models.CharField(_('first name'), max_length=150)
    last_name = models.CharField(_('last name'), max_length=150)
    pup_webmail = models.EmailField(_('PUP webmail'), unique=True)
    email_verified = models.BooleanField(default=False)
    
    objects = StudentUserManager()
    
    USERNAME_FIELD = 'student_number'
    REQUIRED_FIELDS = ['pup_webmail', 'first_name', 'last_name']
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.student_number})"

# Verification code model for email validation and password reset
class VerificationCode(models.Model):
    user = models.ForeignKey(StudentUser, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    purpose = models.CharField(max_length=20, choices=[
        ('email_verification', 'Email Verification'),
        ('password_reset', 'Password Reset')
    ])
    
    def is_valid(self):
        # Check if code is less than 3 minutes old
        from django.utils import timezone
        return (timezone.now() - self.created_at).total_seconds() < 180  # 3 minutes