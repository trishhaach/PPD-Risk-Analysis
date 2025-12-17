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