from pydantic import BaseModel, EmailStr, field_validator


class SignupSchema(BaseModel):
    name: str
    email: EmailStr
    password: str
    confirmPassword: str

    @field_validator("confirmPassword")
    def passwords_match(cls, v, info):
        password = info.data.get("password") if info and getattr(info, "data", None) else None
        if password is not None and v != password:
            raise ValueError("Passwords do not match")
        return v


class LoginSchema(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordSchema(BaseModel):
    oldPassword: str
    newPassword: str


class ForgotPasswordSchema(BaseModel):
    email: EmailStr


class ResetPasswordSchema(BaseModel):
    token: str
    newPassword: str


class UpdateNameSchema(BaseModel):
    name: str


class EPDSAnswerSchema(BaseModel):
    """
    Schema for EPDS screening submission.
    Each question answer should be 0, 1, 2, or 3.
    """
    q1: int  # I have been able to laugh and see the funny side of things
    q2: int  # I have looked forward with enjoyment to things
    q3: int  # I have blamed myself unnecessarily when things went wrong
    q4: int  # I have been anxious or worried for no good reason
    q5: int  # I have felt scared or panicky for no very good reason
    q6: int  # Things have been getting on top of me
    q7: int  # I have been so unhappy that I have had difficulty sleeping
    q8: int  # I have felt sad or miserable
    q9: int  # I have been so unhappy that I have been crying
    q10: int  # The thought of harming myself has occurred to me
    
    @field_validator('q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7', 'q8', 'q9', 'q10')
    def validate_answer(cls, v):
        if v not in [0, 1, 2, 3]:
            raise ValueError('Each answer must be 0, 1, 2, or 3')
        return v