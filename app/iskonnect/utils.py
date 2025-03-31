# iskonnect/utils.py
import random
import string
from django.core.mail import send_mail
from django.conf import settings
from .models import VerificationCode

def generate_verification_code():
    """Generate a random 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(user, purpose):
    try:
        code = generate_verification_code()
        
        # Save the code
        VerificationCode.objects.filter(user=user, purpose=purpose).delete()
        verification = VerificationCode.objects.create(
            user=user,
            code=code,
            purpose=purpose
        )
        
        # Define email content
        subject = 'Verify your iSKonnect account'
        message = f'Your verification code is: {code}\nThis code will expire in 3 minutes.'
        
        # Send and print status
        sent = send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.pup_webmail],
            fail_silently=False,
        )
        print(f"Email sent: {sent} to {user.pup_webmail}")
        return sent
    except Exception as e:
        print(f"Error sending email: {e}")
        return False