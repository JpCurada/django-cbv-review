# iskonnect/validators.py
from pydantic import BaseModel, Field, validator, EmailStr
import re

class StudentNumberValidator(BaseModel):
    student_number: str
    
    @validator('student_number')
    def validate_student_number(cls, v):
        pattern = r'^20\d{2}-\d{5}-[A-Z]{2}-\d$'
        if not re.match(pattern, v):
            raise ValueError('Student number must be in format YYYY-NNNNN-CC-D')
        return v

class PUPEmailValidator(BaseModel):
    pup_webmail: EmailStr
    
    @validator('pup_webmail')
    def validate_pup_email(cls, v):
        if not v.endswith('@iskolarngbayan.pup.edu.ph'):
            raise ValueError('Email must end with @iskolarngbayan.pup.edu.ph')
        return v

class PasswordValidator(BaseModel):
    password: str = Field(..., min_length=8)

class SignupValidator(StudentNumberValidator, PUPEmailValidator, PasswordValidator):
    first_name: str
    last_name: str
    
    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v

class LoginValidator(StudentNumberValidator):
    password: str