from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hashlib
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session

from database import init_db, engine
from models import User
from schemas import SignupSchema, LoginSchema, ChangePasswordSchema, ForgotPasswordSchema, ResetPasswordSchema

# Set up logging for production debugging
# Configure logging to output to stdout (works with Render and other platforms)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load environment variables from .env file (if it exists)
# This works locally and in deployment (deployment platforms can override with their own env vars)
load_dotenv()

# SECURITY: Load secrets from environment variables.
# In production, set strong random values for these:
#   SAKHI_SECRET_KEY, SAKHI_PASSWORD_SALT
# These can be set via .env file locally or environment variables in deployment
SECRET_KEY = os.getenv("SAKHI_SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
PASSWORD_SALT = os.getenv("SAKHI_PASSWORD_SALT", "dev-salt-change-me")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SAKHI_EMAIL_ADDRESS = os.getenv("SAKHI_EMAIL_ADDRESS")
SAKHI_EMAIL_PASSWORD = os.getenv("SAKHI_EMAIL_PASSWORD")


def get_password_hash(password: str) -> str:
    """
    Hash password using SHA-256 with a static salt.
    This supports arbitrarily long passwords.
    """
    value = (PASSWORD_SALT + password).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password


def send_welcome_email(to_email: str, name: str) -> None:
    """
    Send a welcome email to the given address.

    IMPORTANT: Requires environment variables:
      - SAKHI_EMAIL_ADDRESS
      - SAKHI_EMAIL_PASSWORD

    Configure this Gmail account to use an app password (recommended) instead of the raw login password.
    """
    if not SAKHI_EMAIL_ADDRESS or not SAKHI_EMAIL_PASSWORD:
        logger.warning(f"Email credentials not set, skipping welcome email to {to_email}")
        return

    msg = EmailMessage()
    msg["From"] = SAKHI_EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = "Welcome to Sakhi"

    msg.set_content(
        f"Hi {name},\n\n"
        "Thank you for choosing us! Welcome to Sakhi.\n\n"
        "With love,\n"
        "The Sakhi Team"
    )

    try:
        logger.info(f"Sending welcome email to: {to_email}")
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SAKHI_EMAIL_ADDRESS, SAKHI_EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"Welcome email sent successfully to: {to_email}")
    except Exception as e:
        logger.error(f"ERROR sending welcome email to {to_email}: {str(e)}", exc_info=True)
        # Avoid raising from background email failures
        return


def create_reset_token(email: str, expires_minutes: int = 30) -> str:
    """
    Create a short-lived token specifically for password reset.
    """
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode = {"sub": email, "scope": "password_reset", "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def send_password_reset_email(to_email: str, token: str) -> None:
    """
    Send password reset email.

    While there is no frontend yet, we just send the raw token in the email.
    In production, you would replace this with a real frontend URL, e.g.:
      https://your-frontend-url.com/reset-password?token=...
    """
    logger.info(f"send_password_reset_email called for: {to_email}")
    if not SAKHI_EMAIL_ADDRESS or not SAKHI_EMAIL_PASSWORD:
        logger.error(f"Email credentials not set. SAKHI_EMAIL_ADDRESS={bool(SAKHI_EMAIL_ADDRESS)}, SAKHI_EMAIL_PASSWORD={bool(SAKHI_EMAIL_PASSWORD)}")
        return

    msg = EmailMessage()
    msg["From"] = SAKHI_EMAIL_ADDRESS
    msg["To"] = to_email
    msg["Subject"] = "Reset your Sakhi password"

    msg.set_content(
        "You requested to reset your Sakhi password.\n\n"
        "For now (development mode), here is your reset token:\n"
        f"{token}\n\n"
        "Use this token in the /reset-password API.\n\n"
        "If you did not request this, you can ignore this email.\n"
    )

    try:
        logger.info(f"Attempting to send password reset email to: {to_email}")
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SAKHI_EMAIL_ADDRESS, SAKHI_EMAIL_PASSWORD)
            server.send_message(msg)
        logger.info(f"Password reset email sent successfully to: {to_email}")
    except Exception as e:
        logger.error(f"ERROR sending password reset email to {to_email}: {str(e)}", exc_info=True)
        return


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    with Session(engine) as session:
        user = session.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        return user

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

# Allow your web (Next.js) and mobile (Flutter) apps to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later you can restrict to specific domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"message": "Hello, FastAPI is running!"}

@app.post("/signup")
def signup(data: SignupSchema, background_tasks: BackgroundTasks):
    try:
        with Session(engine) as session:
            existing_user = session.query(User).filter(User.email == data.email).first()
            if existing_user:
                raise HTTPException(status_code=400, detail="Email already registered")

            hashed_password = get_password_hash(data.password)

            new_user = User(
                name=data.name,
                email=data.email,
                password=hashed_password,
            )

            session.add(new_user)
            session.commit()
            session.refresh(new_user)

            # Send welcome email in the background so signup response is fast
            background_tasks.add_task(send_welcome_email, to_email=new_user.email, name=new_user.name)

            return {
                "message": f"User {data.name} signed up successfully!",
                "email": data.email,
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection error: {str(e)}")

@app.post("/login")
def login(data: LoginSchema):
    try:
        with Session(engine) as session:
            user = session.query(User).filter(User.email == data.email).first()
            if not user:
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            if not verify_password(data.password, user.password):
                raise HTTPException(status_code=401, detail="Invalid email or password")
            
            access_token = create_access_token({"sub": user.email})

            return {
                "message": "Login successful!",
                "email": user.email,
                "name": user.name,
                "access_token": access_token,
                "token_type": "bearer",
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection error: {str(e)}")


@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordSchema, background_tasks: BackgroundTasks):
    """
    Request a password reset link to be sent to the user's email.
    Always return a generic success message to avoid leaking which emails exist.
    """
    try:
        logger.info(f"Password reset requested for email: {data.email}")
        with Session(engine) as session:
            user = session.query(User).filter(User.email == data.email).first()

            if user:
                # Only generate and send token if user exists
                reset_token = create_reset_token(user.email)
                logger.info(f"Generated reset token for user: {user.email}")
                logger.info(f"Adding background task to send email to: {user.email}")
                background_tasks.add_task(
                    send_password_reset_email,
                    to_email=user.email,
                    token=reset_token,
                )
                logger.info(f"Background task added successfully for: {user.email}")
            else:
                logger.info(f"No user found with email: {data.email}")

        # Always respond success, even if user not found
        return {"message": "If this email is registered, a reset link has been sent."}
    except Exception as e:
        logger.error(f"Error in forgot-password endpoint: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error processing password reset: {str(e)}")


@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema):
    """
    Reset the user's password using a token from the email.
    """
    try:
        # Verify and decode token
        try:
            payload = jwt.decode(data.token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            raise HTTPException(status_code=400, detail="Invalid or expired token")

        if payload.get("scope") != "password_reset":
            raise HTTPException(status_code=400, detail="Invalid reset token")

        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Invalid reset token")

        with Session(engine) as session:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            user.password = get_password_hash(data.newPassword)
            session.add(user)
            session.commit()

        return {"message": "Password reset successful"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Error resetting password: {str(e)}")


@app.get("/profile-view")
def read_profile(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "name": current_user.name,
    }


@app.patch("/change-password")
def change_password(data: ChangePasswordSchema, current_user: User = Depends(get_current_user)):
    try:
        with Session(engine) as session:
            user = session.query(User).filter(User.id == current_user.id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # Verify old password
            if not verify_password(data.oldPassword, user.password):
                raise HTTPException(status_code=401, detail="Old password is incorrect")

            # Set new password
            user.password = get_password_hash(data.newPassword)
            session.add(user)
            session.commit()

            return {
                "message": "Password changed successfully"
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection error: {str(e)}")


@app.delete("/delete-account")
def delete_account(current_user: User = Depends(get_current_user)):
    try:
        with Session(engine) as session:
            user = session.query(User).filter(User.id == current_user.id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            session.delete(user)
            session.commit()

            return {
                "message": "Account deleted successfully"
            }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database connection error: {str(e)}")