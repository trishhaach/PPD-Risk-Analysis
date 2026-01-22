from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hashlib
import logging
import os
import uuid
from typing import Optional, List

from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
import json
import httpx
from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks, Query, File, UploadFile
from fastapi.responses import JSONResponse

# Set up logging first (before Supabase import)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Supabase imports - handle gracefully if not available
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    Client = None
    logger.warning("Supabase package not fully installed. Storage will use local fallback.")
import firebase_admin
from firebase_admin import credentials, auth
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session

from database import init_db, engine
from hybrid import HybridScreener
from models import (
    User,
    EPDSResult,
    PPDRiskAssessment,
    Blog,
    Category,
    CommunityPost,
    Group,
    GroupPost,
    GroupMember,
    CommunityPostLike,
    GroupPostLike,
    CommunityComment,
    GroupComment,
    CommunityCommentLike,
    GroupCommentLike,
    ContributorProfile,
    ContributorEducation,
    ContributorExperience,
    ContributorCertification,
    ContributorExpertise,
    ContributorPublication,
    Article,
)
from schemas import (
    SignupSchema,
    LoginSchema,
    ChangePasswordSchema,
    ForgotPasswordSchema,
    ResetPasswordSchema,
    UpdateNameSchema,
    EPDSAnswerSchema,
    PPDRiskAssessmentRequestSchema,
    PPDRiskAssessmentResponseSchema,
    HybridScreeningRequestSchema,
    BlogCreateSchema,
    BlogUpdateSchema,
    BlogListItemSchema,
    BlogDetailSchema,
    CreatedBySchema,
    CreatePostSchema,
    CategoryResponseSchema,
    UserResponseSchema,
    ViewPostResponseSchema,
    CreateCategorySchema,
    UpdatePostSchema,
    CreateGroupSchema,
    UpdateGroupSchema,
    ViewGroupResponseSchema,
    CreateGroupPostSchema,
    UpdateGroupPostSchema,
    ViewGroupPostResponseSchema,
    CreateCommentSchema,
    ViewCommentSchema,
    CreateGroupCommentSchema,
    ViewGroupCommentSchema,
    Step1BasicProfileSchema,
    Step2EducationSchema,
    Step3ExperienceSchema,
    Step4CertificationsSchema,
    Step5ExpertiseAndPublicationsSchema,
    ContributorProfileResponseSchema,
    CreateArticleSchema,
    UpdateArticleSchema,
)

# Logging is already set up above (before Supabase import)

# Load environment variables from .env file (if it exists)
# This works locally and in deployment (deployment platforms can override with their own env vars)
load_dotenv()

# SECURITY: Load secrets from environment variables.
# In production, set strong random values for these:
#   SAKHI_SECRET_KEY, SAKHI_PASSWORD_SALT
# These can be set via .env file locally or environment variables in deployment
SECRET_KEY = os.getenv("SAKHI_SECRET_KEY", "dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600  # 10 hours
PASSWORD_SALT = os.getenv("SAKHI_PASSWORD_SALT", "dev-salt-change-me")

# ==================== ML (PPD Risk Assessment) Configuration ====================
# Base URL for the external ML service (FastAPI hosted on HuggingFace Space)
PPD_ML_BASE_URL = os.getenv("PPD_ML_BASE_URL", "https://appledog00-ppd-risk-api.hf.space").rstrip("/")
# Optional: set this to skip discovery and directly call the ML POST endpoint
PPD_ML_PREDICT_URL = os.getenv("PPD_ML_PREDICT_URL")  # full URL e.g. https://.../predict

# Cache discovered predict URL to avoid fetching openapi.json on every request
_ppd_ml_predict_url_cache: Optional[str] = None

# The form config your ML engineer provided (returned to frontend as-is)
PPD_RISK_FORM_CONFIG = {
    "app_title": "PPD Risk Assessment",
    "description": "Enter patient details to screen for Postpartum Depression risk.",
    "model_file": "catboost_model_top20.cbm",
    "fields": [
        {"id": "Need for Support", "label": "Select Need for Support", "type": "dropdown", "options": ["high", "low", "medium", "none"], "default": "high"},
        {"id": "Recieved Support", "label": "Select Recieved Support", "type": "dropdown", "options": ["high", "low", "medium"], "default": "high"},
        {"id": "Abuse", "label": "Select Abuse", "type": "dropdown", "options": ["no", "yes"], "default": "no"},
        {"id": "Disease before pregnancy", "label": "Select Disease before pregnancy", "type": "dropdown", "options": ["chronic disease", "non-chronic disease", "none"], "default": "chronic disease"},
        {"id": "Pregnancy plan", "label": "Select Pregnancy plan", "type": "dropdown", "options": ["no", "yes"], "default": "no"},
        {"id": "Relationship with the in-laws", "label": "Select Relationship with the in-laws", "type": "dropdown", "options": ["bad", "friendly", "good", "neutral", "poor"], "default": "bad"},
        {"id": "Relationship with husband", "label": "Select Relationship with husband", "type": "dropdown", "options": ["bad", "friendly", "good", "neutral", "poor"], "default": "bad"},
        {"id": "Occupation before latest pregnancy", "label": "Select Occupation before latest pregnancy", "type": "dropdown", "options": ["business", "doctor", "house wife", "housewife", "other", "service", "student", "teacher"], "default": "business"},
        {"id": "Major changes or losses during pregnancy", "label": "Select Major changes or losses during pregnancy", "type": "dropdown", "options": ["no", "yes"], "default": "no"},
        {"id": "Relationship with the newborn", "label": "Select Relationship with the newborn", "type": "dropdown", "options": ["bad", "good", "neutral", "very good"], "default": "bad"},
        {"id": "Family type", "label": "Select Family type", "type": "dropdown", "options": ["joint", "nuclear"], "default": "joint"},
        {"id": "Diseases during pregnancy", "label": "Select Diseases during pregnancy", "type": "dropdown", "options": ["chronic disease", "non-chronic disease", "none"], "default": "chronic disease"},
        {"id": "Relationship between father and newborn", "label": "Select Relationship between father and newborn", "type": "dropdown", "options": ["bad", "good", "neutral", "very good"], "default": "bad"},
        {"id": "Husband's education level", "label": "Select Husband's education level", "type": "dropdown", "options": ["College", "High School", "High school", "Primary School", "Primary school", "University"], "default": "College"},
        {"id": "Trust and share feelings", "label": "Select Trust and share feelings", "type": "dropdown", "options": ["no", "yes"], "default": "no"},
        {"id": "Birth compliancy", "label": "Select Birth compliancy", "type": "dropdown", "options": ["no", "yes"], "default": "no"},
        {"id": "Education Level", "label": "Select Education Level", "type": "dropdown", "options": ["college", "high school", "primary school", "university", "unknown"], "default": "college"},
        {"id": "Occupation After Your Latest Childbirth", "label": "Select Occupation After Your Latest Childbirth", "type": "dropdown", "options": ["business", "doctor", "house wife", "housewife", "other", "service", "student", "teacher"], "default": "business"},
        {"id": "Addiction", "label": "Select Addiction", "type": "dropdown", "options": ["drinking", "drugs", "none", "smoking"], "default": "none"},
        {"id": "Age", "label": "Enter Age", "type": "number", "min": 18.0, "max": 45.0, "default": 18.0},
    ],
}


def _discover_ppd_ml_predict_url() -> str:
    """
    Discover the ML service POST endpoint by reading its OpenAPI spec.
    This avoids hardcoding the predict path (since you only gave /docs).
    """
    global _ppd_ml_predict_url_cache

    if PPD_ML_PREDICT_URL:
        return PPD_ML_PREDICT_URL

    if _ppd_ml_predict_url_cache:
        return _ppd_ml_predict_url_cache

    openapi_url = f"{PPD_ML_BASE_URL}/openapi.json"
    try:
        resp = httpx.get(openapi_url, timeout=15)
        resp.raise_for_status()
        spec = resp.json()
    except Exception as e:
        logger.error(f"Failed to fetch ML OpenAPI spec from {openapi_url}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail="ML service is unavailable (cannot read OpenAPI spec)")

    paths = spec.get("paths", {}) or {}
    post_paths: List[str] = []
    for path, methods in paths.items():
        if isinstance(methods, dict) and "post" in methods:
            post_paths.append(path)

    if not post_paths:
        logger.error(f"No POST paths found in ML OpenAPI spec from {openapi_url}")
        raise HTTPException(status_code=503, detail="ML service OpenAPI has no POST endpoint")

    # Prefer something that looks like a predict endpoint; otherwise first POST path.
    preferred = None
    for p in post_paths:
        if any(k in p.lower() for k in ["predict", "ppd", "risk", "assess"]):
            preferred = p
            break
    chosen_path = preferred or post_paths[0]

    _ppd_ml_predict_url_cache = f"{PPD_ML_BASE_URL}{chosen_path}"
    logger.info(f"Discovered PPD ML predict URL: {_ppd_ml_predict_url_cache}")
    return _ppd_ml_predict_url_cache


# Supabase Storage Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")  # Service role key (for admin operations)
SUPABASE_STORAGE_BUCKET = os.getenv("SUPABASE_STORAGE_BUCKET", "blog-images")
USE_SUPABASE_STORAGE = os.getenv("USE_SUPABASE_STORAGE", "true").lower() == "true"  # Default to true if using Supabase

# Initialize Supabase client if credentials are provided
supabase_client: Optional[Client] = None
if SUPABASE_AVAILABLE and USE_SUPABASE_STORAGE and SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase_client = create_client(SUPABASE_URL, SUPABASE_KEY)
        logger.info("Supabase Storage client initialized successfully")
    except Exception as e:
        logger.warning(f"Failed to initialize Supabase client: {str(e)}. Falling back to local storage.")
        supabase_client = None
elif USE_SUPABASE_STORAGE and not SUPABASE_AVAILABLE:
    logger.warning("Supabase Storage requested but package not available. Using local storage.")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

SAKHI_EMAIL_ADDRESS = os.getenv("SAKHI_EMAIL_ADDRESS", "sakhihealth25@gmail.com")
SAKHI_EMAIL_PASSWORD = os.getenv("SAKHI_EMAIL_PASSWORD")

# Firebase configuration
FIREBASE_SERVICE_ACCOUNT_KEY = os.getenv("FIREBASE_SERVICE_ACCOUNT_KEY")

# Initialize Firebase Admin SDK (optional - only if service account key is provided)
firebase_app = None
if FIREBASE_SERVICE_ACCOUNT_KEY:
    try:
        # If the key is provided as JSON string in env var, parse it
        service_account_info = json.loads(FIREBASE_SERVICE_ACCOUNT_KEY)
        cred = credentials.Certificate(service_account_info)
        firebase_app = firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully")
    except json.JSONDecodeError:
        # If it's a file path instead, try that
        try:
            cred = credentials.Certificate(FIREBASE_SERVICE_ACCOUNT_KEY)
            firebase_app = firebase_admin.initialize_app(cred)
            logger.info("Firebase Admin SDK initialized successfully from file")
        except Exception as e:
            logger.warning(f"Failed to initialize Firebase: {e}. Firebase features will be disabled.")
    except Exception as e:
        logger.warning(f"Failed to initialize Firebase: {e}. Firebase features will be disabled.")
else:
    logger.info("Firebase service account key not provided. Firebase features will be disabled.")


def get_password_hash(password: str) -> str:
    """
    Hash password using SHA-256 with a static salt.
    This supports arbitrarily long passwords.
    """
    value = (PASSWORD_SALT + password).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password


def generate_firebase_token(user_id: int) -> Optional[str]:
    """
    Generate a Firebase custom token for a user.
    Returns None if Firebase is not configured.
    """
    if not firebase_app:
        return None
    
    try:
        # Convert user ID to string for Firebase UID
        uid = str(user_id)
        custom_token = auth.create_custom_token(uid)
        return custom_token.decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating Firebase token: {e}", exc_info=True)
        return None


def send_welcome_email(to_email: str, name: str) -> None:
    """
    Send a welcome email to the given address using Gmail SMTP.
    
    IMPORTANT: Requires environment variables:
      - SAKHI_EMAIL_ADDRESS (Gmail address: sakhihealth25@gmail.com)
      - SAKHI_EMAIL_PASSWORD (Gmail app password)
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
    Send password reset email using Gmail SMTP.
    
    While there is no frontend yet, we just send the raw token in the email.
    In production, you would replace this with a real frontend URL, e.g.:
      https://your-frontend-url.com/reset-password?token=...
      
    IMPORTANT: Requires environment variables:
      - SAKHI_EMAIL_ADDRESS (Gmail address: sakhihealth25@gmail.com)
      - SAKHI_EMAIL_PASSWORD (Gmail app password)
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
        logger.info(f"Attempting to validate token (first 20 chars): {token[:20] if token else 'None'}...")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        logger.info(f"Token decoded successfully for email: {email}")
        if email is None:
            logger.warning("Token payload missing 'sub' field")
            raise credentials_exception
    except JWTError as e:
        logger.error(f"JWT decode error: {str(e)}")
        raise credentials_exception

    with Session(engine) as session:
        user = session.query(User).filter(User.email == email).first()
        if user is None:
            logger.warning(f"User not found for email: {email}")
            raise credentials_exception
        logger.info(f"User authenticated successfully: {user.email}")
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
                role=data.role
            )

            session.add(new_user)
            session.commit()
            session.refresh(new_user)

            # Send welcome email in the background so signup response is fast
            background_tasks.add_task(send_welcome_email, to_email=new_user.email, name=new_user.name)
            
            # Generate access token and Firebase custom token
            access_token = create_access_token({"sub": new_user.email})
            firebase_token = generate_firebase_token(new_user.id)

            response_data = {
                "message": f"User {data.name} signed up successfully!",
                "email": data.email,
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": new_user.id,
                    "email": new_user.email,
                    "name": new_user.name,
                    "role": new_user.role
                }
            }
            
            # Add Firebase token if available
            if firebase_token:
                response_data["firebase_token"] = firebase_token

            return response_data
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
            
            # Generate Firebase custom token
            firebase_token = generate_firebase_token(user.id)

            response_data = {
                "message": "Login successful!",
                "email": user.email,
                "name": user.name,
                "role": user.role,
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name,
                    "role": user.role
                }
            }
            
            # Add Firebase token if available
            if firebase_token:
                response_data["firebase_token"] = firebase_token
            
            return response_data
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


@app.post("/logout")
def logout(current_user: User = Depends(get_current_user)):
    """
    Logout the authenticated user.
    Note: Since we use stateless JWT tokens, the client should delete the token.
    This endpoint confirms logout and logs the action.
    """
    try:
        logger.info(f"User {current_user.email} logged out")
        return {
            "message": "Logged out successfully",
            "email": current_user.email
        }
    except Exception as e:
        logger.error(f"Error in logout endpoint: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error processing logout: {str(e)}")


@app.get("/profile-view")
def read_profile(current_user: User = Depends(get_current_user)):
    return {
        "email": current_user.email,
        "name": current_user.name,
        "role": current_user.role,
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


@app.patch("/update-name")
def update_name(data: UpdateNameSchema, current_user: User = Depends(get_current_user)):
    """
    Update the authenticated user's name.
    """
    try:
        with Session(engine) as session:
            user = session.query(User).filter(User.id == current_user.id).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            # Update name
            user.name = data.name
            session.add(user)
            session.commit()
            session.refresh(user)

            return {
                "message": "Name updated successfully",
                "name": user.name,
                "email": user.email
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


def calculate_epds_score(answers: EPDSAnswerSchema) -> tuple[int, str]:
    """
    Calculate EPDS total score and risk level.
    
    Scoring rules:
    - Questions 1, 2, 4 (*): Scored 0, 1, 2, 3 (top to bottom)
    - Questions 3, 5-10: Scored 3, 2, 1, 0 (top to bottom)
    
    The frontend should send answers as 0-3 based on the scoring criteria.
    We just sum them up here.
    
    Risk levels:
    - 0-9: Low risk
    - 10-12: Moderate risk
    - 13-30: High risk
    """
    total = (
        answers.q1 + answers.q2 + answers.q3 + answers.q4 + answers.q5 +
        answers.q6 + answers.q7 + answers.q8 + answers.q9 + answers.q10
    )
    
    # Determine risk level
    if total <= 9:
        risk_level = "low"
    elif total <= 12:
        risk_level = "moderate"
    else:
        risk_level = "high"
    
    return total, risk_level


@app.post("/epds-screen")
def submit_epds_screening(
    answers: EPDSAnswerSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Submit EPDS screening answers and get calculated results.
    
    The frontend should send answers as integers 0-3 based on:
    - Questions 1, 2, 4: 0 (best) to 3 (worst)
    - Questions 3, 5-10: 3 (worst) to 0 (best)
    """
    try:
        # Calculate total score and risk level
        total_score, risk_level = calculate_epds_score(answers)
        
        # Store result in database
        with Session(engine) as session:
            epds_result = EPDSResult(
                user_id=current_user.id,
                q1=answers.q1,
                q2=answers.q2,
                q3=answers.q3,
                q4=answers.q4,
                q5=answers.q5,
                q6=answers.q6,
                q7=answers.q7,
                q8=answers.q8,
                q9=answers.q9,
                q10=answers.q10,
                total_score=total_score,
                risk_level=risk_level
            )
            
            session.add(epds_result)
            session.commit()
            session.refresh(epds_result)
            
            return {
                "message": "EPDS screening completed successfully",
                "result": {
                    "id": epds_result.id,
                    "total_score": total_score,
                    "risk_level": risk_level,
                    "answers": {
                        "q1": answers.q1,
                        "q2": answers.q2,
                        "q3": answers.q3,
                        "q4": answers.q4,
                        "q5": answers.q5,
                        "q6": answers.q6,
                        "q7": answers.q7,
                        "q8": answers.q8,
                        "q9": answers.q9,
                        "q10": answers.q10,
                    },
                    "created_at": epds_result.created_at.isoformat()
                },
                "interpretation": {
                    "low": "Score 0-9: Low risk of postpartum depression",
                    "moderate": "Score 10-12: Moderate risk - consider monitoring or support",
                    "high": "Score 13-30: High risk - please consult with a healthcare provider"
                }[risk_level]
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in EPDS screening: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error processing EPDS screening: {str(e)}")


@app.get("/epds-screen/history")
def get_epds_history(current_user: User = Depends(get_current_user)):
    """
    Get the user's EPDS screening history.
    """
    try:
        with Session(engine) as session:
            results = session.query(EPDSResult).filter(
                EPDSResult.user_id == current_user.id
            ).order_by(EPDSResult.created_at.desc()).all()
            
            return {
                "history": [
                    {
                        "id": result.id,
                        "total_score": result.total_score,
                        "risk_level": result.risk_level,
                        "created_at": result.created_at.isoformat()
                    }
                    for result in results
                ],
                "count": len(results)
            }
    except Exception as e:
        logger.error(f"Error fetching EPDS history: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching screening history: {str(e)}")


@app.get("/hybrid-screen/history")
def get_hybrid_screening_history(current_user: User = Depends(get_current_user)):
    """
    Get the user's hybrid screening history.
    Returns hybrid screening results that combine EPDS and ML-based symptom assessment.
    """
    try:
        from sqlalchemy import func, and_
        screener = HybridScreener()
        
        with Session(engine) as session:
            # Get all EPDS results for the user, ordered by most recent
            epds_results = session.query(EPDSResult).filter(
                EPDSResult.user_id == current_user.id
            ).order_by(EPDSResult.created_at.desc()).all()
            
            history = []
            
            for epds in epds_results:
                # Find matching PPD risk assessment within 5 seconds
                matching_ppd = session.query(PPDRiskAssessment).filter(
                    PPDRiskAssessment.user_id == current_user.id,
                    func.abs(
                        func.extract('epoch', epds.created_at - PPDRiskAssessment.created_at)
                    ) <= 5
                ).first()
                
                if matching_ppd:
                    try:
                        # Extract ML probability from stored PPD response
                        ml_result = json.loads(matching_ppd.ml_response_json)
                        ml_raw_probability = _extract_ml_probability(ml_result)
                        
                        # Reconstruct EPDS responses
                        epds_responses = [
                            epds.q1, epds.q2, epds.q3, epds.q4, epds.q5,
                            epds.q6, epds.q7, epds.q8, epds.q9, epds.q10
                        ]
                        
                        # Re-run hybrid screening to get the result
                        result = screener.screen(
                            epds_responses=epds_responses,
                            ml_raw_probability=ml_raw_probability
                        )
                        
                        # Determine clinical recommendation
                        recommendation = "Consult clinical guidelines."
                        if result.risk_label.value == "Critical":
                            recommendation = "IMMEDIATE EMERGENCY INTERVENTION REQUIRED."
                        elif result.risk_label.value == "High":
                            recommendation = "Clinical assessment recommended. Consider referral."
                        elif result.risk_label.value == "Moderate":
                            recommendation = "Enhanced monitoring recommended. Re-screen in 2 weeks."
                        elif result.risk_label.value == "Low":
                            recommendation = "Routine postpartum care."
                        
                        history.append({
                            "id": epds.id,
                            "risk_label": result.risk_label.value,
                            "final_probability": result.final_probability,
                            "is_critical": (result.risk_label.value == "Critical"),
                            "clinical_recommendation": recommendation,
                            "epds_total_score": epds.total_score,
                            "epds_risk_level": epds.risk_level,
                            "fusion_method": result.fusion_method,
                            "explanation": result.explanation,
                            "metrics": result.detailed_metrics,
                            "audit": {
                                "timestamp": result.audit_record.timestamp,
                                "decision_path": result.audit_record.decision_path,
                                "is_discordant": result.audit_record.is_discordant,
                                "uncertainty_flag": result.audit_record.uncertainty_flag
                            },
                            "created_at": epds.created_at.isoformat()
                        })
                    except (ValueError, KeyError, json.JSONDecodeError) as e:
                        # Skip this entry if we can't process it
                        logger.warning(f"Could not process hybrid screening {epds.id}: {str(e)}")
                        continue
            
            return {
                "history": history,
                "count": len(history)
            }
    except Exception as e:
        logger.error(f"Error fetching hybrid screening history: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching hybrid screening history: {str(e)}")


@app.get("/screening/count")
def get_screening_counts(current_user: User = Depends(get_current_user)):
    """
    Get the total count of screenings done by the user.
    Returns counts for EPDS, PPD risk assessments, and hybrid screenings.
    """
    try:
        with Session(engine) as session:
            # Count EPDS screenings
            epds_count = session.query(EPDSResult).filter(
                EPDSResult.user_id == current_user.id
            ).count()
            
            # Count PPD risk assessments
            ppd_count = session.query(PPDRiskAssessment).filter(
                PPDRiskAssessment.user_id == current_user.id
            ).count()
            
            # Count hybrid screenings: EPDSResult records that have a corresponding PPDRiskAssessment
            # created within 5 seconds (hybrid screenings create both in the same transaction)
            from sqlalchemy import func, and_
            # Get all EPDS results for the user
            epds_results = session.query(EPDSResult).filter(
                EPDSResult.user_id == current_user.id
            ).all()
            
            # Count how many have a matching PPDRiskAssessment within 5 seconds
            hybrid_count = 0
            for epds in epds_results:
                matching_ppd = session.query(PPDRiskAssessment).filter(
                    PPDRiskAssessment.user_id == current_user.id,
                    func.abs(
                        func.extract('epoch', epds.created_at - PPDRiskAssessment.created_at)
                    ) <= 5
                ).first()
                if matching_ppd:
                    hybrid_count += 1
            
            return {
                "epds_screening_count": epds_count,
                "ppd_risk_assessment_count": ppd_count,
                "hybrid_screening_count": hybrid_count,
                "total_screening_count": epds_count + ppd_count
            }
    except Exception as e:
        logger.error(f"Error fetching screening counts: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching screening counts: {str(e)}")


@app.get("/epds-screen/{result_id}")
def get_epds_result(result_id: int, current_user: User = Depends(get_current_user)):
    """
    Get a specific EPDS screening result by ID.
    """
    try:
        with Session(engine) as session:
            result = session.query(EPDSResult).filter(
                EPDSResult.id == result_id,
                EPDSResult.user_id == current_user.id
            ).first()
            
            if not result:
                raise HTTPException(status_code=404, detail="EPDS screening result not found")
            
            return {
                "id": result.id,
                "total_score": result.total_score,
                "risk_level": result.risk_level,
                "answers": {
                    "q1": result.q1,
                    "q2": result.q2,
                    "q3": result.q3,
                    "q4": result.q4,
                    "q5": result.q5,
                    "q6": result.q6,
                    "q7": result.q7,
                    "q8": result.q8,
                    "q9": result.q9,
                    "q10": result.q10,
                },
                "created_at": result.created_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching EPDS result: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching screening result: {str(e)}")


# ==================== ML-based PPD Risk (Symptom Questionnaire) ====================

@app.get("/symptom/ppd-risk/form")
def get_ppd_risk_form():
    """
    Returns the questionnaire (questions + options) for the PPD Risk Assessment feature.
    Frontend uses this to build the UI form dynamically.
    """
    return PPD_RISK_FORM_CONFIG


@app.post("/symptom/ppd-risk/assess", response_model=PPDRiskAssessmentResponseSchema)
def assess_ppd_risk(
    payload: PPDRiskAssessmentRequestSchema,
    current_user: User = Depends(get_current_user),
):
    """
    Runs ML-based PPD risk assessment by forwarding the user's answers to the external ML service.
    Stores both request + ML response in DB for history.
    """
    try:
        predict_url = _discover_ppd_ml_predict_url()

        # Convert to dict with ML-friendly keys (aliases)
        ml_payload = payload.model_dump(by_alias=True)

        # Call the ML service
        try:
            # The ML service expects a top-level "data" field (per its 422 error: missing body.data)
            ml_resp = httpx.post(predict_url, json={"data": ml_payload}, timeout=30)
            ml_resp.raise_for_status()
            ml_result = ml_resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"ML service error: {str(e)}; body={e.response.text}", exc_info=True)
            raise HTTPException(status_code=503, detail="ML service returned an error")
        except Exception as e:
            logger.error(f"Failed calling ML service at {predict_url}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=503, detail="ML service is unavailable")

        # Store in DB
        with Session(engine) as session:
            record = PPDRiskAssessment(
                user_id=current_user.id,
                ml_endpoint=predict_url,
                answers_json=json.dumps(ml_payload),
                ml_response_json=json.dumps(ml_result),
            )
            session.add(record)
            session.commit()
            session.refresh(record)

            return {
                "id": f"ppd_risk_{record.id}",
                "result": ml_result,
                "createdAt": record.created_at.isoformat(),
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error assessing PPD risk: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error assessing PPD risk: {str(e)}")


@app.get("/symptom/ppd-risk/history")
def get_ppd_risk_history(
    current_user: User = Depends(get_current_user),
    limit: int = Query(20, ge=1, le=100),
):
    """
    Returns the user's ML-based PPD risk assessment history (latest first).
    """
    try:
        with Session(engine) as session:
            rows = (
                session.query(PPDRiskAssessment)
                .filter(PPDRiskAssessment.user_id == current_user.id)
                .order_by(PPDRiskAssessment.created_at.desc())
                .limit(limit)
                .all()
            )

            return [
                {
                    "id": f"ppd_risk_{r.id}",
                    "result": json.loads(r.ml_response_json) if r.ml_response_json else {},
                    "createdAt": r.created_at.isoformat(),
                }
                for r in rows
            ]
    except Exception as e:
        logger.error(f"Error fetching PPD risk history: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching PPD risk history: {str(e)}")


@app.get("/symptom/ppd-risk/{result_id}")
def get_ppd_risk_result(
    result_id: int,
    current_user: User = Depends(get_current_user),
):
    """
    Get a specific ML-based PPD risk assessment result by numeric ID.
    """
    try:
        with Session(engine) as session:
            r = (
                session.query(PPDRiskAssessment)
                .filter(PPDRiskAssessment.id == result_id, PPDRiskAssessment.user_id == current_user.id)
                .first()
            )
            if not r:
                raise HTTPException(status_code=404, detail="PPD risk result not found")
            
            return {
                "id": f"ppd_risk_{r.id}",
                "result": json.loads(r.ml_response_json) if r.ml_response_json else {},
                "createdAt": r.created_at.isoformat(),
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching PPD risk result: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching PPD risk result: {str(e)}")


def _extract_ml_probability(ml_result: dict) -> float:
    """
    Extract raw probability from ML service response.
    Tries common field names: 'probability', 'prediction', 'score', 'risk_score', 'prob'
    """
    # Try common field names
    possible_fields = ['probability', 'prediction', 'score', 'risk_score', 'prob', 'risk_probability']
    
    for field in possible_fields:
        if field in ml_result:
            value = ml_result[field]
            # Handle nested structures
            if isinstance(value, dict):
                # Try to find a numeric value in nested dict
                for k, v in value.items():
                    if isinstance(v, (int, float)) and 0 <= v <= 1:
                        return float(v)
            elif isinstance(value, (int, float)):
                # Ensure value is between 0 and 1
                prob = float(value)
                if prob < 0 or prob > 1:
                    # If value is > 1, might be percentage (0-100), convert to 0-1
                    if prob > 1:
                        prob = prob / 100.0
                return prob
    
    # If no standard field found, try to find any numeric value between 0-1
    for key, value in ml_result.items():
        if isinstance(value, (int, float)):
            prob = float(value)
            if 0 <= prob <= 1:
                return prob
            elif prob > 1 and prob <= 100:
                return prob / 100.0
    
    raise ValueError(f"Could not extract probability from ML response. Available keys: {list(ml_result.keys())}")


@app.post("/screening/hybrid")
def perform_hybrid_screening(
    request: HybridScreeningRequestSchema,
    current_user: User = Depends(get_current_user)
):
    """
    **Perform Hybrid Screening**
    
    Combines EPDS (Clinical Authority) and ML-based symptom assessment (Risk Augmentation)
    using Priority-Based Hierarchy:
    1. **Critical:** Q10=3 (Immediate Override)
    2. **High:** EPDS >= 13 (Clinical Dominance)
    3. **Discordant:** Low EPDS / High ML (Precision-Aware Split Logic)
    4. **Standard:** Weighted Fusion
    
    ⚠️ **DISCLAIMER**: This is a screening aid, NOT a diagnostic tool. 
    Final decisions require clinical judgment.
    """
    try:
        # Initialize hybrid screener
        screener = HybridScreener()
        
        # Step 1: Get ML raw probability by calling ML service
        predict_url = _discover_ppd_ml_predict_url()
        
        # Extract symptom questionnaire answers from request
        symptom_payload = {
            "Need for Support": request.need_for_support,
            "Recieved Support": request.recieved_support,
            "Abuse": request.abuse,
            "Disease before pregnancy": request.disease_before_pregnancy,
            "Occupation before latest pregnancy": request.occupation_before_latest_pregnancy,
            "Pregnancy plan": request.pregnancy_plan,
            "Relationship with husband": request.relationship_with_husband,
            "Major changes or losses during pregnancy": request.major_changes_or_losses_during_pregnancy,
            "Relationship with the in-laws": request.relationship_with_in_laws,
            "Birth compliancy": request.birth_compliancy,
            "Relationship between father and newborn": request.relationship_between_father_and_newborn,
            "Education Level": request.education_level,
            "Family type": request.family_type,
            "Diseases during pregnancy": request.diseases_during_pregnancy,
            "Trust and share feelings": request.trust_and_share_feelings,
            "Relationship with the newborn": request.relationship_with_newborn,
            "Occupation After Your Latest Childbirth": request.occupation_after_latest_childbirth,
            "Age": request.age,
            "Addiction": request.addiction,
            "Husband's education level": request.husbands_education_level
        }
        
        # Call ML service
        try:
            ml_resp = httpx.post(predict_url, json={"data": symptom_payload}, timeout=30)
            ml_resp.raise_for_status()
            ml_result = ml_resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"ML service error: {str(e)}; body={e.response.text}", exc_info=True)
            raise HTTPException(status_code=503, detail="ML service returned an error")
        except Exception as e:
            logger.error(f"Failed calling ML service at {predict_url}: {str(e)}", exc_info=True)
            raise HTTPException(status_code=503, detail="ML service is unavailable")
        
        # Extract ML raw probability
        try:
            ml_raw_probability = _extract_ml_probability(ml_result)
        except ValueError as e:
            logger.error(f"Error extracting ML probability: {str(e)}", exc_info=True)
            raise HTTPException(status_code=500, detail=f"Could not extract probability from ML response: {str(e)}")
        
        # Step 2: Perform hybrid screening
        result = screener.screen(
            epds_responses=request.epds_responses,
            ml_raw_probability=ml_raw_probability
        )
        
        # Step 3: Determine clinical recommendation
        recommendation = "Consult clinical guidelines."
        if result.risk_label.value == "Critical":
            recommendation = "IMMEDIATE EMERGENCY INTERVENTION REQUIRED."
        elif result.risk_label.value == "High":
            recommendation = "Clinical assessment recommended. Consider referral."
        elif result.risk_label.value == "Moderate":
            recommendation = "Enhanced monitoring recommended. Re-screen in 2 weeks."
        elif result.risk_label.value == "Low":
            recommendation = "Routine postpartum care."
        
        # Step 4: Store both EPDS and PPD risk assessment records for history
        with Session(engine) as session:
            # Calculate EPDS-specific risk level for storage
            epds_total = sum(request.epds_responses)
            if epds_total < 10:
                epds_risk_level = "low"
            elif epds_total < 13:
                epds_risk_level = "moderate"
            else:
                epds_risk_level = "high"
            
            # Store EPDS result
            epds_result = EPDSResult(
                user_id=current_user.id,
                q1=request.epds_responses[0],
                q2=request.epds_responses[1],
                q3=request.epds_responses[2],
                q4=request.epds_responses[3],
                q5=request.epds_responses[4],
                q6=request.epds_responses[5],
                q7=request.epds_responses[6],
                q8=request.epds_responses[7],
                q9=request.epds_responses[8],
                q10=request.epds_responses[9],
                total_score=epds_total,
                risk_level=epds_risk_level  # Store EPDS-specific risk level
            )
            session.add(epds_result)
            
            # Store PPD risk assessment
            ppd_record = PPDRiskAssessment(
                user_id=current_user.id,
                ml_endpoint=predict_url,
                answers_json=json.dumps(symptom_payload),
                ml_response_json=json.dumps(ml_result),
            )
            session.add(ppd_record)
            session.commit()
        
        # Step 5: Return hybrid result
        from hybrid import RiskLevel
        return {
            "risk_label": result.risk_label.value,
            "final_probability": result.final_probability,
            "is_critical": (result.risk_label == RiskLevel.CRITICAL),
            "clinical_recommendation": recommendation,
            "explanation": result.explanation,
            "fusion_method": result.fusion_method,
            "metrics": result.detailed_metrics,
            "audit": {
                "timestamp": result.audit_record.timestamp,
                "decision_path": result.audit_record.decision_path,
                "is_discordant": result.audit_record.is_discordant,
                "uncertainty_flag": result.audit_record.uncertainty_flag
            },
            "system_disclaimer": "Screening aid only. Consult clinical guidelines."
        }
        
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error in hybrid screening: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error performing hybrid screening: {str(e)}")


# ==================== BLOG API ENDPOINTS ====================

# ==================== BLOG APIs - COMMENTED OUT ====================

# @app.get("/blogs")
# def get_all_blogs(
#     page: int = Query(1, ge=1, description="Page number (starts from 1)"),
#     limit: int = Query(10, ge=1, le=100, description="Number of blogs per page"),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Get paginated list of all blogs.
#     """
#     try:
#         with Session(engine) as session:
#             # Calculate offset
#             offset = (page - 1) * limit
#             
#             # Get total count
#             total = session.query(Blog).count()
#             
#             # Get blogs with pagination
#             blogs = session.query(Blog).order_by(Blog.created_at.desc()).offset(offset).limit(limit).all()
#             
#             # Get user info for each blog
#             blog_list = []
#             for blog in blogs:
#                 creator = session.query(User).filter(User.id == blog.created_by_id).first()
#                 if creator:
#                     blog_list.append({
#                         "id": str(blog.id),
#                         "title": blog.title,
#                         "slug": blog.slug,
#                         "cover": blog.cover,
#                         "isPublished": blog.is_published,
#                         "tags": json.loads(blog.tags) if blog.tags else [],
#                         "category": json.loads(blog.category) if blog.category else [],
#                         "createdBy": {
#                             "id": str(creator.id),
#                             "name": creator.name
#                         },
#                         "createdAt": blog.created_at.isoformat(),
#                         "meta": blog.meta
#                     })
#             
#             # Check if there's a next page
#             has_next = (offset + limit) < total
#             
#             return {
#                 "data": blog_list,
#                 "paginate": {
#                     "total": total,
#                     "hasNext": has_next
#                 }
#             }
#     except Exception as e:
#         logger.error(f"Error fetching blogs: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error fetching blogs: {str(e)}")


# @app.get("/blogs/{slug}")
# def get_blog_by_slug(slug: str, current_user: User = Depends(get_current_user)):
#     """
#     Get a single blog by slug for editing.
#     """
#     try:
#         with Session(engine) as session:
#             blog = session.query(Blog).filter(Blog.slug == slug).first()
#             
#             if not blog:
#                 raise HTTPException(status_code=404, detail="Blog not found")
#             
#             creator = session.query(User).filter(User.id == blog.created_by_id).first()
#             if not creator:
#                 raise HTTPException(status_code=404, detail="Blog creator not found")
#             
#             # Parse JSON fields
#             tags = json.loads(blog.tags) if blog.tags else []
#             category = json.loads(blog.category) if blog.category else []
#             toc = json.loads(blog.toc) if blog.toc else None
#             
#             return {
#                 "data": {
#                     "id": str(blog.id),
#                     "title": blog.title,
#                     "slug": blog.slug,
#                     "cover": blog.cover,
#                     "cover_key": blog.cover_key,
#                     "meta": blog.meta,
#                     "desc": blog.desc,
#                     "preview": blog.preview,
#                     "tags": tags,
#                     "category": category,
#                     "toc": toc,
#                     "isPublished": blog.is_published,
#                     "createdBy": {
#                         "id": str(creator.id),
#                         "name": creator.name
#                     },
#                     "createdAt": blog.created_at.isoformat()
#                 }
#             }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error fetching blog: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error fetching blog: {str(e)}")


# @app.post("/blogs")
# def create_blog(blog_data: BlogCreateSchema, current_user: User = Depends(get_current_user)):
#     """
#     Create a new blog.
#     """
#     try:
#         with Session(engine) as session:
#             # Check if slug already exists
#             existing_blog = session.query(Blog).filter(Blog.slug == blog_data.slug).first()
#             if existing_blog:
#                 raise HTTPException(status_code=400, detail="A blog with this slug already exists")
#             
#             # Prepare JSON strings for tags, category, and toc
#             tags_json = json.dumps(blog_data.tags)
#             category_json = json.dumps(blog_data.category)
#             toc_json = json.dumps([toc.model_dump() for toc in blog_data.toc]) if blog_data.toc else None
#             
#             # Create blog
#             new_blog = Blog(
#                 title=blog_data.title,
#                 slug=blog_data.slug,
#                 meta=blog_data.meta,
#                 desc=blog_data.desc,
#                 preview=blog_data.preview,
#                 cover=blog_data.cover,
#                 cover_key=blog_data.cover_key,
#                 tags=tags_json,
#                 category=category_json,
#                 toc=toc_json,
#                 is_published=False,
#                 created_by_id=current_user.id
#             )
#             
#             session.add(new_blog)
#             session.commit()
#             session.refresh(new_blog)
#             
#             # Get creator info
#             creator = session.query(User).filter(User.id == new_blog.created_by_id).first()
#             
#             # Parse JSON fields for response
#             tags = json.loads(new_blog.tags) if new_blog.tags else []
#             category = json.loads(new_blog.category) if new_blog.category else []
#             toc = json.loads(new_blog.toc) if new_blog.toc else None
#             
#             return {
#                 "data": {
#                     "id": str(new_blog.id),
#                     "title": new_blog.title,
#                     "slug": new_blog.slug,
#                     "cover": new_blog.cover,
#                     "cover_key": new_blog.cover_key,
#                     "meta": new_blog.meta,
#                     "desc": new_blog.desc,
#                     "preview": new_blog.preview,
#                     "tags": tags,
#                     "category": category,
#                     "toc": toc,
#                     "isPublished": new_blog.is_published,
#                     "createdBy": {
#                         "id": str(creator.id) if creator else str(current_user.id),
#                         "name": creator.name if creator else current_user.name
#                     },
#                     "createdAt": new_blog.created_at.isoformat()
#                 }
#             }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error creating blog: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error creating blog: {str(e)}")


# @app.patch("/blogs/{id}")
# def update_blog(id: int, blog_data: BlogUpdateSchema, current_user: User = Depends(get_current_user)):
#     """
#     Update an existing blog.
#     """
#     try:
#         with Session(engine) as session:
#             blog = session.query(Blog).filter(Blog.id == id).first()
#             
#             if not blog:
#                 raise HTTPException(status_code=404, detail="Blog not found")
#             
#             # Check if user is the creator (optional: can remove if admins should edit all)
#             if blog.created_by_id != current_user.id:
#                 raise HTTPException(status_code=403, detail="You don't have permission to edit this blog")
#             
#             # Update fields if provided
#             if blog_data.title is not None:
#                 blog.title = blog_data.title
#             if blog_data.slug is not None:
#                 # Check if new slug conflicts with existing blog
#                 existing = session.query(Blog).filter(Blog.slug == blog_data.slug, Blog.id != id).first()
#                 if existing:
#                     raise HTTPException(status_code=400, detail="A blog with this slug already exists")
#                 blog.slug = blog_data.slug
#             if blog_data.meta is not None:
#                 blog.meta = blog_data.meta
#             if blog_data.desc is not None:
#                 blog.desc = blog_data.desc
#             if blog_data.preview is not None:
#                 blog.preview = blog_data.preview
#             if blog_data.cover is not None:
#                 blog.cover = blog_data.cover
#             if blog_data.cover_key is not None:
#                 blog.cover_key = blog_data.cover_key
#             if blog_data.tags is not None:
#                 blog.tags = json.dumps(blog_data.tags)
#             if blog_data.category is not None:
#                 blog.category = json.dumps(blog_data.category)
#             if blog_data.toc is not None:
#                 blog.toc = json.dumps([toc.model_dump() for toc in blog_data.toc])
#             
#             blog.updated_at = datetime.utcnow()
#             
#             session.add(blog)
#             session.commit()
#             session.refresh(blog)
#             
#             # Get creator info
#             creator = session.query(User).filter(User.id == blog.created_by_id).first()
#             
#             # Parse JSON fields
#             tags = json.loads(blog.tags) if blog.tags else []
#             category = json.loads(blog.category) if blog.category else []
#             toc = json.loads(blog.toc) if blog.toc else None
#             
#             return {
#                 "data": {
#                     "id": str(blog.id),
#                     "title": blog.title,
#                     "slug": blog.slug,
#                     "cover": blog.cover,
#                     "cover_key": blog.cover_key,
#                     "meta": blog.meta,
#                     "desc": blog.desc,
#                     "preview": blog.preview,
#                     "tags": tags,
#                     "category": category,
#                     "toc": toc,
#                     "isPublished": blog.is_published,
#                     "createdBy": {
#                         "id": str(creator.id) if creator else str(blog.created_by_id),
#                         "name": creator.name if creator else "Unknown"
#                     },
#                     "createdAt": blog.created_at.isoformat()
#                 }
#             }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error updating blog: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error updating blog: {str(e)}")


# @app.delete("/blogs/{id}")
# def delete_blog(id: int, current_user: User = Depends(get_current_user)):
#     """
#     Delete a blog.
#     """
#     try:
#         with Session(engine) as session:
#             blog = session.query(Blog).filter(Blog.id == id).first()
#             
#             if not blog:
#                 raise HTTPException(status_code=404, detail="Blog not found")
#             
#             # Check if user is the creator (optional: can remove if admins should delete all)
#             if blog.created_by_id != current_user.id:
#                 raise HTTPException(status_code=403, detail="You don't have permission to delete this blog")
#             
#             session.delete(blog)
#             session.commit()
#             
#             return {
#                 "data": {
#                     "success": True,
#                     "message": "Blog deleted successfully"
#                 }
#             }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error deleting blog: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error deleting blog: {str(e)}")


# @app.patch("/blogs/publish/{id}")
# def toggle_publish_blog(id: int, current_user: User = Depends(get_current_user)):
#     """
#     Toggle publish status of a blog (publish or unpublish).
#     """
#     try:
#         with Session(engine) as session:
#             blog = session.query(Blog).filter(Blog.id == id).first()
#             
#             if not blog:
#                 raise HTTPException(status_code=404, detail="Blog not found")
#             
#             # Check if user is the creator
#             if blog.created_by_id != current_user.id:
#                 raise HTTPException(status_code=403, detail="You don't have permission to publish/unpublish this blog")
#             
#             # Toggle publish status
#             blog.is_published = not blog.is_published
#             blog.updated_at = datetime.utcnow()
#             
#             session.add(blog)
#             session.commit()
#             
#             status_message = "published" if blog.is_published else "unpublished"
#             
#             return {
#                 "data": {
#                     "success": True,
#                     "message": f"Blog {status_message} successfully"
#                 }
#             }
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error toggling publish status: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error toggling publish status: {str(e)}")


# @app.post("/blogs/upload-blog-file")
# async def upload_blog_file(
#     file: UploadFile = File(...),
#     path: Optional[str] = Query(None, description="Storage path/folder name"),
#     current_user: User = Depends(get_current_user)
# ):
#     """
#     Upload images (cover images, content images) for blog.
#     Returns the storage key/path to be used in cover_key field.
#     Uses S3 in production, local storage in development.
#     """
#     try:
#         # Validate file type (images only)
#         if not file.content_type or not file.content_type.startswith('image/'):
#             raise HTTPException(status_code=400, detail="File must be an image")
#         
#         # Generate unique filename
#         file_extension = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
#         timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
#         unique_filename = f"{timestamp}_{current_user.id}{file_extension}"
#         
#         # Read file content
#         content = await file.read()
#         
#         # Determine storage path
#         storage_folder = path or "blog-images"
#         storage_key = f"{storage_folder}/{unique_filename}"
#         
#         # Use Supabase Storage if configured, otherwise use local storage
#         if supabase_client and USE_SUPABASE_STORAGE:
#             # Upload to Supabase Storage
#             try:
#                 # Upload file to Supabase Storage
#                 response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).upload(
#                     path=storage_key,
#                     file=content,
#                     file_options={"content-type": file.content_type, "upsert": "true"}
#                 )
#                 
#                 # Get public URL
#                 public_url_response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).get_public_url(storage_key)
#                 public_url = public_url_response
#                 
#                 logger.info(f"File uploaded to Supabase Storage: {storage_key}")
#                 
#                 return {
#                     "key": storage_key,
#                     "url": public_url  # Return both key and URL for convenience
#                 }
#             except Exception as e:
#                 logger.error(f"Supabase Storage upload error: {str(e)}", exc_info=True)
#                 raise HTTPException(status_code=503, detail=f"Error uploading to Supabase Storage: {str(e)}")
#         else:
#             # Local storage fallback (for development)
#             upload_dir = os.path.join("uploads", storage_folder)
#             os.makedirs(upload_dir, exist_ok=True)
#             
#             file_path = os.path.join(upload_dir, unique_filename)
#             
#             # Save file locally
#             with open(file_path, "wb") as buffer:
#                 buffer.write(content)
#             
#             logger.info(f"File saved locally: {file_path}")
#             
#             return {
#                 "key": storage_key,
#                 "url": f"/uploads/{storage_key}"  # Relative URL for local files
#             }
#             
#     except HTTPException:
#         raise
#     except Exception as e:
#         logger.error(f"Error uploading file: {str(e)}", exc_info=True)
#         raise HTTPException(status_code=503, detail=f"Error uploading file: {str(e)}")


# ==================== COMMUNITY API ENDPOINTS ====================

@app.post("/community/create-post")
def create_post(data: CreatePostSchema, current_user: User = Depends(get_current_user)):
    """
    Create a new community post/feed.
    """
    try:
        with Session(engine) as session:
            # Validate category exists
            # Handle categoryId as "cat_001" format or integer
            category_id = None
            if data.categoryId.startswith("cat_"):
                try:
                    category_id = int(data.categoryId.replace("cat_", ""))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            else:
                try:
                    category_id = int(data.categoryId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            
            category = session.query(Category).filter(Category.id == category_id).first()
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            
            # Create new post
            new_post = CommunityPost(
                title=data.title,
                body=data.body,
                image=data.image,
                tags=json.dumps(data.tags),
                category_id=category_id,
                post_type=data.isAnonymous,
                user_id=current_user.id
            )
            
            session.add(new_post)
            session.commit()
            session.refresh(new_post)
            
            return {
                "message": "Post created successfully",
                "id": f"post_{new_post.id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating post: {str(e)}")


@app.get("/community/view-post")
def view_posts(current_user: User = Depends(get_current_user)):
    """
    Get all community posts/feeds.
    """
    try:
        with Session(engine) as session:
            posts = session.query(CommunityPost).order_by(CommunityPost.created_at.desc()).all()
            
            post_list = []
            for post in posts:
                # Get user info
                user = session.query(User).filter(User.id == post.user_id).first()
                if not user:
                    continue
                
                # Get category info
                category = session.query(Category).filter(Category.id == post.category_id).first()
                if not category:
                    continue

                # Likes info - use stored count
                has_liked = session.query(CommunityPostLike).filter(
                    CommunityPostLike.post_id == post.id,
                    CommunityPostLike.user_id == current_user.id
                ).first() is not None
                
                # Check if post is anonymous (post_type stores isAnonymous value)
                if post.post_type:  # True means anonymous
                    user_info = {
                        "id": "anonymous",
                        "name": "Anonymous"
                    }
                else:  # False means not anonymous
                    user_info = {
                        "id": f"user_{user.id}",
                        "name": user.name
                    }
                
                post_list.append({
                    "id": f"post_{post.id}",
                    "title": post.title,
                    "body": post.body,
                    "image": post.image,
                    "tags": json.loads(post.tags) if post.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "isAnonymous": post.post_type,
                    "likeCount": post.like_count,
                    "hasLiked": has_liked,
                    "user": user_info,
                    "postedTime": post.created_at.isoformat()
                })
            
            return post_list
    except Exception as e:
        logger.error(f"Error fetching posts: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching posts: {str(e)}")


@app.post("/community/toggle-like/{post_id}")
def toggle_community_post_like(post_id: int, current_user: User = Depends(get_current_user)):
    """
    Like/unlike a community post.
    If the user has already liked the post, this will unlike it.
    Updates and returns the stored likeCount and hasLiked.
    """
    try:
        with Session(engine) as session:
            post = session.query(CommunityPost).filter(CommunityPost.id == post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Post not found")

            existing_like = session.query(CommunityPostLike).filter(
                CommunityPostLike.post_id == post_id,
                CommunityPostLike.user_id == current_user.id
            ).first()

            if existing_like:
                # Unlike - decrement count
                session.delete(existing_like)
                post.like_count = max(0, post.like_count - 1)  # Ensure count doesn't go below 0
                has_liked = False
            else:
                # Like - increment count
                new_like = CommunityPostLike(
                    post_id=post_id,
                    user_id=current_user.id
                )
                session.add(new_like)
                post.like_count = post.like_count + 1
                has_liked = True

            session.add(post)
            session.commit()
            session.refresh(post)

            return {
                "id": f"post_{post.id}",
                "likeCount": post.like_count,
                "hasLiked": has_liked
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling like on community post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error toggling like: {str(e)}")


@app.post("/community/comments")
def create_community_comment(data: CreateCommentSchema, current_user: User = Depends(get_current_user)):
    """
    Create a comment or reply on a community post.
    """
    try:
        with Session(engine) as session:
            # Parse post ID (e.g. "post_1" or "1")
            try:
                if isinstance(data.postId, str) and data.postId.startswith("post_"):
                    post_id = int(data.postId.replace("post_", ""))
                else:
                    post_id = int(data.postId)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid postId format")

            post = session.query(CommunityPost).filter(CommunityPost.id == post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Post not found")

            # Parent comment (for replies)
            parent_comment_id: Optional[int] = None
            if data.parentCommentId:
                try:
                    if data.parentCommentId.startswith("comment_"):
                        parent_comment_id = int(data.parentCommentId.replace("comment_", ""))
                    else:
                        parent_comment_id = int(data.parentCommentId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid parentCommentId format")

                parent = session.query(CommunityComment).filter(CommunityComment.id == parent_comment_id).first()
                if not parent:
                    raise HTTPException(status_code=404, detail="Parent comment not found")

            comment = CommunityComment(
                post_id=post_id,
                user_id=current_user.id,
                text=data.text,
                parent_comment_id=parent_comment_id,
            )

            session.add(comment)
            session.commit()
            session.refresh(comment)
            
            return {
                "message": "Comment created successfully",
                "id": f"comment_{comment.id}",
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating community comment: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating comment: {str(e)}")


@app.get("/community/comments/{post_id}", response_model=List[ViewCommentSchema])
def get_community_comments(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Get comments (and replies) for a community post.
    """
    try:
        with Session(engine) as session:
            # Parse post ID
            try:
                if post_id.startswith("post_"):
                    numeric_post_id = int(post_id.replace("post_", ""))
                else:
                    numeric_post_id = int(post_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid postId format")

            post = session.query(CommunityPost).filter(CommunityPost.id == numeric_post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Post not found")

            comments = (
                session.query(CommunityComment)
                .filter(CommunityComment.post_id == numeric_post_id)
                .order_by(CommunityComment.created_at.asc())
                .all()
            )

            results: List[ViewCommentSchema] = []
            for c in comments:
                user = session.query(User).filter(User.id == c.user_id).first()
                if not user:
                    continue

                like_count = (
                    session.query(CommunityCommentLike)
                    .filter(CommunityCommentLike.comment_id == c.id)
                    .count()
                )
                has_liked = (
                    session.query(CommunityCommentLike)
                    .filter(
                        CommunityCommentLike.comment_id == c.id,
                        CommunityCommentLike.user_id == current_user.id,
                    )
                    .first()
                    is not None
                )

                results.append(
                    ViewCommentSchema(
                        id=f"comment_{c.id}",
                        postId=f"post_{c.post_id}",
                        parentCommentId=f"comment_{c.parent_comment_id}"
                        if c.parent_comment_id is not None
                        else None,
                        text=c.text,
                        user={
                            "id": f"user_{user.id}",
                            "name": user.name,
                            "role": user.role,
                        },
                        likeCount=like_count,
                        hasLiked=has_liked,
                        createdAt=c.created_at.isoformat(),
                    )
                )

            return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching community comments: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching comments: {str(e)}")


@app.post("/community/comments/{comment_id}/toggle-like")
def toggle_community_comment_like(comment_id: int, current_user: User = Depends(get_current_user)):
    """
    Like/unlike a community comment (or reply).
    """
    try:
        with Session(engine) as session:
            comment = session.query(CommunityComment).filter(CommunityComment.id == comment_id).first()
            if not comment:
                raise HTTPException(status_code=404, detail="Comment not found")

            existing = session.query(CommunityCommentLike).filter(
                CommunityCommentLike.comment_id == comment_id,
                CommunityCommentLike.user_id == current_user.id,
            ).first()

            if existing:
                session.delete(existing)
                has_liked = False
            else:
                new_like = CommunityCommentLike(
                    comment_id=comment_id,
                    user_id=current_user.id,
                )
                session.add(new_like)
                has_liked = True

            session.commit()

            like_count = (
                session.query(CommunityCommentLike)
                .filter(CommunityCommentLike.comment_id == comment_id)
                .count()
            )

            return {
                "id": f"comment_{comment.id}",
                "likeCount": like_count,
                "hasLiked": has_liked,
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling like on community comment: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error toggling like: {str(e)}")


@app.patch("/community/update-post/{post_id}")
def update_post(post_id: int, post_data: UpdatePostSchema, current_user: User = Depends(get_current_user)):
    """
    Update an existing community post.
    Only the post creator can update their own post.
    Use the numeric ID (e.g., 1, 2, 3) not "post_1" format.
    """
    try:
        with Session(engine) as session:
            
            post = session.query(CommunityPost).filter(CommunityPost.id == post_id).first()
            
            if not post:
                raise HTTPException(status_code=404, detail="Post not found")
            
            # Check if user is the creator
            if post.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to edit this post")
            
            # Update fields if provided
            if post_data.title is not None:
                post.title = post_data.title
            if post_data.body is not None:
                post.body = post_data.body
            if post_data.tags is not None:
                post.tags = json.dumps(post_data.tags)
            if post_data.image is not None:
                post.image = post_data.image
            if post_data.isAnonymous is not None:
                post.post_type = post_data.isAnonymous
            if post_data.categoryId is not None:
                # Validate category exists
                category_id = None
                if post_data.categoryId.startswith("cat_"):
                    try:
                        category_id = int(post_data.categoryId.replace("cat_", ""))
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                else:
                    try:
                        category_id = int(post_data.categoryId)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                
                category = session.query(Category).filter(Category.id == category_id).first()
                if not category:
                    raise HTTPException(status_code=404, detail="Category not found")
                
                post.category_id = category_id
            
            session.add(post)
            session.commit()
            session.refresh(post)
            
            # Get user and category info for response
            user = session.query(User).filter(User.id == post.user_id).first()
            category = session.query(Category).filter(Category.id == post.category_id).first()
            
            return {
                "message": "Post updated successfully",
                "id": f"post_{post.id}",
                "title": post.title,
                "body": post.body,
                "image": post.image,
                "tags": json.loads(post.tags) if post.tags else [],
                "category": {
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                },
                "isAnonymous": post.post_type,
                "user": {
                    "id": f"user_{user.id}",
                    "name": user.name
                },
                "postedTime": post.created_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error updating post: {str(e)}")


@app.get("/user/posts/count")
def get_user_post_count(current_user: User = Depends(get_current_user)):
    """
    Get the total count of posts created by the current user.
    Returns counts for both community posts and group posts.
    """
    try:
        with Session(engine) as session:
            # Count community posts
            community_post_count = session.query(CommunityPost).filter(
                CommunityPost.user_id == current_user.id
            ).count()
            
            # Count group posts
            group_post_count = session.query(GroupPost).filter(
                GroupPost.user_id == current_user.id
            ).count()
            
            return {
                "community_post_count": community_post_count,
                "group_post_count": group_post_count,
                "total_post_count": community_post_count + group_post_count
            }
    except Exception as e:
        logger.error(f"Error fetching user post count: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching post count: {str(e)}")


@app.get("/user/posts")
def get_user_posts(current_user: User = Depends(get_current_user)):
    """
    Get all posts created by the current user.
    Returns both community posts and group posts with like count and comment count.
    """
    try:
        with Session(engine) as session:
            # Get community posts
            community_posts = session.query(CommunityPost).filter(
                CommunityPost.user_id == current_user.id
            ).order_by(CommunityPost.created_at.desc()).all()
            
            # Get group posts
            group_posts = session.query(GroupPost).filter(
                GroupPost.user_id == current_user.id
            ).order_by(GroupPost.created_at.desc()).all()
            
            post_list = []
            
            # Process community posts
            for post in community_posts:
                # Get category info
                category = session.query(Category).filter(Category.id == post.category_id).first()
                if not category:
                    continue
                
                # Get comment count
                comment_count = session.query(CommunityComment).filter(
                    CommunityComment.post_id == post.id
                ).count()
                
                # Check if current user has liked
                has_liked = session.query(CommunityPostLike).filter(
                    CommunityPostLike.post_id == post.id,
                    CommunityPostLike.user_id == current_user.id
                ).first() is not None
                
                post_list.append({
                    "id": f"post_{post.id}",
                    "type": "community",
                    "title": post.title,
                    "body": post.body,
                    "image": post.image,
                    "tags": json.loads(post.tags) if post.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "isAnonymous": post.post_type,
                    "likeCount": post.like_count,
                    "commentCount": comment_count,
                    "hasLiked": has_liked,
                    "postedTime": post.created_at.isoformat()
                })
            
            # Process group posts
            for post in group_posts:
                # Get category info
                category = session.query(Category).filter(Category.id == post.category_id).first()
                if not category:
                    continue
                
                # Get group info
                group = session.query(Group).filter(Group.id == post.group_id).first()
                if not group:
                    continue
                
                # Get comment count
                comment_count = session.query(GroupComment).filter(
                    GroupComment.post_id == post.id
                ).count()
                
                # Check if current user has liked
                has_liked = session.query(GroupPostLike).filter(
                    GroupPostLike.post_id == post.id,
                    GroupPostLike.user_id == current_user.id
                ).first() is not None
                
                post_list.append({
                    "id": f"post_{post.id}",
                    "type": "group",
                    "groupId": f"group_{post.group_id}",
                    "groupName": group.group_name,
                    "postTitle": post.post_title,
                    "postBody": post.post_body,
                    "image": post.image,
                    "tags": json.loads(post.tags) if post.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "isAnonymous": post.post_type,
                    "likeCount": post.like_count,
                    "commentCount": comment_count,
                    "hasLiked": has_liked,
                    "postedTime": post.created_at.isoformat()
                })
            
            # Sort all posts by creation time (newest first)
            post_list.sort(key=lambda x: x["postedTime"], reverse=True)
            
            return {
                "posts": post_list,
                "total_count": len(post_list)
            }
    except Exception as e:
        logger.error(f"Error fetching user posts: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching user posts: {str(e)}")


@app.delete("/community/delete-post/{post_id}")
def delete_community_post(post_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete a community post.
    Only the post creator can delete their own post.
    Use the numeric ID (e.g., 1, 2, 3) not "post_1" format.
    """
    try:
        with Session(engine) as session:
            post = session.query(CommunityPost).filter(CommunityPost.id == post_id).first()
            
            if not post:
                raise HTTPException(status_code=404, detail="Community post not found")
            
            # Check if user is the creator
            if post.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to delete this post")
            
            session.delete(post)
            session.commit()
            
            return {
                "message": "Community post deleted successfully",
                "id": f"post_{post_id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting community post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error deleting community post: {str(e)}")


@app.post("/community/create-categories")
def create_category(data: CreateCategorySchema):
    """
    Create a new category for community posts.
    Public endpoint (no authentication required).
    """
    try:
        with Session(engine) as session:
            # Check if category with same name already exists
            existing = session.query(Category).filter(Category.name == data.name).first()
            if existing:
                raise HTTPException(status_code=400, detail="Category with this name already exists")
            
            # Create new category
            new_category = Category(name=data.name)
            session.add(new_category)
            session.commit()
            session.refresh(new_category)
            
            return {
                "message": "Category created successfully",
                "id": f"cat_{new_category.id:03d}",
                "name": new_category.name
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating category: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating category: {str(e)}")


@app.get("/community/category")
def get_categories():
    """
    Get all categories for community posts.
    Public endpoint (no authentication required).
    """
    try:
        with Session(engine) as session:
            categories = session.query(Category).order_by(Category.name).all()
            
            category_list = []
            for category in categories:
                category_list.append({
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                })
            
            return category_list
    except Exception as e:
        logger.error(f"Error fetching categories: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching categories: {str(e)}")


@app.post("/community/upload-post-image")
async def upload_community_post_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Upload images for community posts.
    Returns the image URL to be used in the create-post API's image field.
    Uses Supabase Storage in production, local storage in development.
    """
    try:
        # Validate file type (images only)
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Generate unique filename
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{current_user.id}{file_extension}"
        
        # Read file content
        content = await file.read()
        
        # Determine storage path
        storage_folder = "community-post-images"
        storage_key = f"{storage_folder}/{unique_filename}"
        
        # Use Supabase Storage if configured, otherwise use local storage
        if supabase_client and USE_SUPABASE_STORAGE:
            # Upload to Supabase Storage
            try:
                # Upload file to Supabase Storage
                response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).upload(
                    path=storage_key,
                    file=content,
                    file_options={"content-type": file.content_type, "upsert": "true"}
                )
                
                # Get public URL
                public_url_response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).get_public_url(storage_key)
                public_url = public_url_response
                
                logger.info(f"Community post image uploaded to Supabase Storage: {storage_key}")
                
                return {
                    "url": public_url  # Return URL to use in create-post API
                }
            except Exception as e:
                logger.error(f"Supabase Storage upload error: {str(e)}", exc_info=True)
                raise HTTPException(status_code=503, detail=f"Error uploading to Supabase Storage: {str(e)}")
        else:
            # Local storage fallback (for development)
            upload_dir = os.path.join("uploads", storage_folder)
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, unique_filename)
            
            # Save file locally
            with open(file_path, "wb") as buffer:
                buffer.write(content)
            
            logger.info(f"Community post image saved locally: {file_path}")
            
            return {
                "url": f"/uploads/{storage_key}"  # Relative URL for local files
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading community post image: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error uploading image: {str(e)}")


@app.post("/upload-group-image")
async def upload_group_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Upload images for groups.
    Returns the image URL to be used in the create-group API's image field.
    Uses Supabase Storage in production, local storage in development.
    """
    try:
        # Validate file type (images only)
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Generate unique filename
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{current_user.id}{file_extension}"
        
        # Read file content
        content = await file.read()
        
        # Determine storage path
        storage_folder = "group-images"
        storage_key = f"{storage_folder}/{unique_filename}"
        
        # Use Supabase Storage if configured, otherwise use local storage
        if supabase_client and USE_SUPABASE_STORAGE:
            # Upload to Supabase Storage
            try:
                # Upload file to Supabase Storage
                response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).upload(
                    path=storage_key,
                    file=content,
                    file_options={"content-type": file.content_type, "upsert": "true"}
                )
                
                # Get public URL
                public_url_response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).get_public_url(storage_key)
                public_url = public_url_response
                
                logger.info(f"Group image uploaded to Supabase Storage: {storage_key}")
                
                return {
                    "url": public_url  # Return URL to use in create-group API
                }
            except Exception as e:
                logger.error(f"Supabase Storage upload error: {str(e)}", exc_info=True)
                raise HTTPException(status_code=503, detail=f"Error uploading to Supabase Storage: {str(e)}")
        else:
            # Local storage fallback (for development)
            upload_dir = os.path.join("uploads", storage_folder)
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, unique_filename)
            
            # Save file locally
            with open(file_path, "wb") as buffer:
                buffer.write(content)
            
            logger.info(f"Group image saved locally: {file_path}")
            
            return {
                "url": f"/uploads/{storage_key}"  # Relative URL for local files
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading group image: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error uploading image: {str(e)}")


# ==================== GROUP API ENDPOINTS ====================

@app.post("/create-group")
def create_group(data: CreateGroupSchema, current_user: User = Depends(get_current_user)):
    """
    Create a new group.
    """
    try:
        with Session(engine) as session:
            # Validate category exists
            category_id = None
            if data.categoryId.startswith("cat_"):
                try:
                    category_id = int(data.categoryId.replace("cat_", ""))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            else:
                try:
                    category_id = int(data.categoryId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            
            category = session.query(Category).filter(Category.id == category_id).first()
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            
            # Create new group
            new_group = Group(
                group_name=data.groupName,
                group_description=data.groupDescription,
                image=data.image,
                category_id=category_id,
                created_by_id=current_user.id
            )
            
            session.add(new_group)
            session.commit()
            session.refresh(new_group)
            
            # Automatically add creator as a member
            group_member = GroupMember(
                group_id=new_group.id,
                user_id=current_user.id
            )
            session.add(group_member)
            session.commit()
            
            return {
                "message": "Group created successfully",
                "groupId": f"group_{new_group.id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating group: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating group: {str(e)}")


@app.post("/join-group/{group_id}")
def join_group(group_id: int, current_user: User = Depends(get_current_user)):
    """
    Join a group. Adds the current user as a member of the specified group.
    Use the numeric ID (e.g., 1, 2, 3) not "group_1" format.
    """
    try:
        with Session(engine) as session:
            # Check if group exists
            group = session.query(Group).filter(Group.id == group_id).first()
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")

            # Check if user is already a member
            existing_member = session.query(GroupMember).filter(
                GroupMember.group_id == group_id,
                GroupMember.user_id == current_user.id
            ).first()

            if existing_member:
                raise HTTPException(status_code=400, detail="You are already a member of this group")

            # Add user as member
            new_member = GroupMember(
                group_id=group_id,
                user_id=current_user.id
            )
            session.add(new_member)
            session.commit()
            session.refresh(new_member)

            return {
                "message": "Successfully joined the group",
                "groupId": f"group_{group.id}",
                "groupName": group.group_name
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error joining group: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error joining group: {str(e)}")


@app.get("/user/my-groups/created")
def get_my_created_groups(current_user: User = Depends(get_current_user)):
    """
    Get all groups created by the current user.
    """
    try:
        with Session(engine) as session:
            groups = session.query(Group).filter(
                Group.created_by_id == current_user.id
            ).order_by(Group.created_at.desc()).all()
            
            group_list = []
            for group in groups:
                # Get category info
                category = session.query(Category).filter(Category.id == group.category_id).first()
                if not category:
                    continue
                
                group_list.append({
                    "groupId": f"group_{group.id}",
                    "groupName": group.group_name,
                    "groupDescription": group.group_description,
                    "image": group.image,
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "createdAt": group.created_at.isoformat()
                })
            
            return group_list
    except Exception as e:
        logger.error(f"Error fetching created groups: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching created groups: {str(e)}")


@app.get("/user/my-groups/joined")
def get_my_joined_groups(current_user: User = Depends(get_current_user)):
    """
    Get all groups the current user has joined (including groups they created).
    """
    try:
        with Session(engine) as session:
            # Get all group memberships for current user
            memberships = session.query(GroupMember).filter(
                GroupMember.user_id == current_user.id
            ).order_by(GroupMember.joined_at.desc()).all()
            
            group_list = []
            for membership in memberships:
                # Get group details
                group = session.query(Group).filter(Group.id == membership.group_id).first()
                if not group:
                    continue
                
                # Get category info
                category = session.query(Category).filter(Category.id == group.category_id).first()
                if not category:
                    continue
                
                # Get creator info
                creator = session.query(User).filter(User.id == group.created_by_id).first()
                if not creator:
                    continue
                
                group_list.append({
                    "groupId": f"group_{group.id}",
                    "groupName": group.group_name,
                    "groupDescription": group.group_description,
                    "image": group.image,
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "createdBy": {
                        "id": f"user_{creator.id}",
                        "name": creator.name
                    },
                    "joinedAt": membership.joined_at.isoformat(),
                    "createdAt": group.created_at.isoformat()
                })
            
            return group_list
    except Exception as e:
        logger.error(f"Error fetching joined groups: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching joined groups: {str(e)}")


@app.get("/view-group")
def view_groups(current_user: User = Depends(get_current_user)):
    """
    Get all groups.
    """
    try:
        with Session(engine) as session:
            groups = session.query(Group).order_by(Group.created_at.desc()).all()
            
            group_list = []
            for group in groups:
                # Get creator info
                creator = session.query(User).filter(User.id == group.created_by_id).first()
                if not creator:
                    continue
                
                # Get category info
                category = session.query(Category).filter(Category.id == group.category_id).first()
                if not category:
                    continue
                
                group_list.append({
                    "groupId": f"group_{group.id}",
                    "groupName": group.group_name,
                    "groupDescription": group.group_description,
                    "image": group.image,
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "createdBy": {
                        "id": f"user_{creator.id}",
                        "name": creator.name
                    },
                    "createdAt": group.created_at.isoformat()
                })
            
            return group_list
    except Exception as e:
        logger.error(f"Error fetching groups: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching groups: {str(e)}")


@app.patch("/update-group/{group_id}")
def update_group(group_id: int, group_data: UpdateGroupSchema, current_user: User = Depends(get_current_user)):
    """
    Update an existing group.
    Only the group creator can update their own group.
    Use the numeric ID (e.g., 1, 2, 3) not "group_1" format.
    """
    try:
        with Session(engine) as session:
            group = session.query(Group).filter(Group.id == group_id).first()
            
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")
            
            # Check if user is the creator
            if group.created_by_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to edit this group")
            
            # Update fields if provided
            if group_data.groupName is not None:
                group.group_name = group_data.groupName
            if group_data.groupDescription is not None:
                group.group_description = group_data.groupDescription
            if group_data.image is not None:
                group.image = group_data.image
            if group_data.categoryId is not None:
                # Validate category exists
                category_id = None
                if group_data.categoryId.startswith("cat_"):
                    try:
                        category_id = int(group_data.categoryId.replace("cat_", ""))
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                else:
                    try:
                        category_id = int(group_data.categoryId)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                
                category = session.query(Category).filter(Category.id == category_id).first()
                if not category:
                    raise HTTPException(status_code=404, detail="Category not found")
                
                group.category_id = category_id
            
            session.add(group)
            session.commit()
            session.refresh(group)
            
            # Get creator and category info for response
            creator = session.query(User).filter(User.id == group.created_by_id).first()
            category = session.query(Category).filter(Category.id == group.category_id).first()
            
            return {
                "message": "Group updated successfully",
                "groupId": f"group_{group.id}",
                "groupName": group.group_name,
                "groupDescription": group.group_description,
                "image": group.image,
                "category": {
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                },
                "createdBy": {
                    "id": f"user_{creator.id}",
                    "name": creator.name
                },
                "createdAt": group.created_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating group: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error updating group: {str(e)}")


@app.delete("/delete-group/{group_id}")
def delete_group(group_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete a group.
    Only the group creator can delete their own group.
    Use the numeric ID (e.g., 1, 2, 3) not "group_1" format.
    """
    try:
        with Session(engine) as session:
            group = session.query(Group).filter(Group.id == group_id).first()
            
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")
            
            # Check if user is the creator
            if group.created_by_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to delete this group")
            
            session.delete(group)
            session.commit()
            
            return {
                "message": "Group deleted successfully",
                "groupId": f"group_{group_id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting group: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error deleting group: {str(e)}")


# ==================== GROUP POST API ENDPOINTS ====================

@app.post("/group/upload-post-image")
async def upload_group_post_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Upload images for group posts.
    Returns the image URL to be used in the group/create-post API's image field.
    Uses Supabase Storage in production, local storage in development.
    """
    try:
        # Validate file type (images only)
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Generate unique filename
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{current_user.id}{file_extension}"
        
        # Read file content
        content = await file.read()
        
        # Determine storage path
        storage_folder = "group-post-images"
        storage_key = f"{storage_folder}/{unique_filename}"
        
        # Use Supabase Storage if configured, otherwise use local storage
        if supabase_client and USE_SUPABASE_STORAGE:
            # Upload to Supabase Storage
            try:
                # Upload file to Supabase Storage
                response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).upload(
                    path=storage_key,
                    file=content,
                    file_options={"content-type": file.content_type, "upsert": "true"}
                )
                
                # Get public URL
                public_url_response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).get_public_url(storage_key)
                public_url = public_url_response
                
                logger.info(f"Group post image uploaded to Supabase Storage: {storage_key}")
                
                return {
                    "url": public_url  # Return URL to use in group/create-post API
                }
            except Exception as e:
                logger.error(f"Supabase Storage upload error: {str(e)}", exc_info=True)
                raise HTTPException(status_code=503, detail=f"Error uploading to Supabase Storage: {str(e)}")
        else:
            # Local storage fallback (for development)
            upload_dir = os.path.join("uploads", storage_folder)
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, unique_filename)
            
            # Save file locally
            with open(file_path, "wb") as buffer:
                buffer.write(content)
            
            logger.info(f"Group post image saved locally: {file_path}")
            
            return {
                "url": f"/uploads/{storage_key}"  # Relative URL for local files
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading group post image: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error uploading image: {str(e)}")


@app.post("/group/create-post")
def create_group_post(data: CreateGroupPostSchema, current_user: User = Depends(get_current_user)):
    """
    Create a new post within a group.
    """
    try:
        with Session(engine) as session:
            # Validate group exists
            group_id = None
            if data.groupId.startswith("group_"):
                try:
                    group_id = int(data.groupId.replace("group_", ""))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid groupId format")
            else:
                try:
                    group_id = int(data.groupId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid groupId format")
            
            group = session.query(Group).filter(Group.id == group_id).first()
            if not group:
                raise HTTPException(status_code=404, detail="Group not found")
            
            # Validate category exists
            category_id = None
            if data.categoryId.startswith("cat_"):
                try:
                    category_id = int(data.categoryId.replace("cat_", ""))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            else:
                try:
                    category_id = int(data.categoryId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            
            category = session.query(Category).filter(Category.id == category_id).first()
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            
            # Create new group post
            new_post = GroupPost(
                post_title=data.postTitle,
                post_body=data.postBody,
                image=data.image,
                tags=json.dumps(data.tags),
                category_id=category_id,
                post_type=data.isAnonymous,
                group_id=group_id,
                user_id=current_user.id
            )
            
            session.add(new_post)
            session.commit()
            session.refresh(new_post)
            
            return {
                "message": "Group post created successfully",
                "id": f"post_{new_post.id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating group post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating group post: {str(e)}")


@app.get("/group/view-post")
def view_group_posts(current_user: User = Depends(get_current_user)):
    """
    Get all group posts.
    """
    try:
        with Session(engine) as session:
            posts = session.query(GroupPost).order_by(GroupPost.created_at.desc()).all()
            
            post_list = []
            for post in posts:
                # Get user info
                user = session.query(User).filter(User.id == post.user_id).first()
                if not user:
                    continue
                
                # Get category info
                category = session.query(Category).filter(Category.id == post.category_id).first()
                if not category:
                    continue

                # Likes info - use stored count
                has_liked = session.query(GroupPostLike).filter(
                    GroupPostLike.post_id == post.id,
                    GroupPostLike.user_id == current_user.id
                ).first() is not None
                
                # Check if post is anonymous (post_type stores isAnonymous value)
                if post.post_type:  # True means anonymous
                    user_info = {
                        "id": "anonymous",
                        "name": "Anonymous"
                    }
                else:  # False means not anonymous
                    user_info = {
                        "id": f"user_{user.id}",
                        "name": user.name
                    }
                
                post_list.append({
                    "id": f"post_{post.id}",
                    "groupId": f"group_{post.group_id}",
                    "postTitle": post.post_title,
                    "postBody": post.post_body,
                    "image": post.image,
                    "tags": json.loads(post.tags) if post.tags else [],
                    "isAnonymous": post.post_type,
                    "likeCount": post.like_count,
                    "hasLiked": has_liked,
                    "category": {
                        "id": f"cat_{category.id:03d}",
                        "name": category.name
                    },
                    "user": user_info,
                    "postedTime": post.created_at.isoformat()
                })
            
            return post_list
    except Exception as e:
        logger.error(f"Error fetching group posts: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching group posts: {str(e)}")


@app.patch("/group/update-post/{post_id}")
def update_group_post(post_id: int, post_data: UpdateGroupPostSchema, current_user: User = Depends(get_current_user)):
    """
    Update an existing group post.
    Only the post creator can update their own post.
    Use the numeric ID (e.g., 1, 2, 3) not "post_1" format.
    """
    try:
        with Session(engine) as session:
            post = session.query(GroupPost).filter(GroupPost.id == post_id).first()
            
            if not post:
                raise HTTPException(status_code=404, detail="Group post not found")
            
            # Check if user is the creator
            if post.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to edit this post")
            
            # Update fields if provided
            if post_data.postTitle is not None:
                post.post_title = post_data.postTitle
            if post_data.postBody is not None:
                post.post_body = post_data.postBody
            if post_data.tags is not None:
                post.tags = json.dumps(post_data.tags)
            if post_data.image is not None:
                post.image = post_data.image
            if post_data.isAnonymous is not None:
                post.post_type = post_data.isAnonymous
            if post_data.categoryId is not None:
                # Validate category exists
                category_id = None
                if post_data.categoryId.startswith("cat_"):
                    try:
                        category_id = int(post_data.categoryId.replace("cat_", ""))
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                else:
                    try:
                        category_id = int(post_data.categoryId)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                
                category = session.query(Category).filter(Category.id == category_id).first()
                if not category:
                    raise HTTPException(status_code=404, detail="Category not found")
                
                post.category_id = category_id
            
            session.add(post)
            session.commit()
            session.refresh(post)
            
            # Get user and category info for response
            user = session.query(User).filter(User.id == post.user_id).first()
            category = session.query(Category).filter(Category.id == post.category_id).first()
            
            return {
                "message": "Group post updated successfully",
                "id": f"post_{post.id}",
                "groupId": f"group_{post.group_id}",
                "postTitle": post.post_title,
                "postBody": post.post_body,
                "image": post.image,
                "tags": json.loads(post.tags) if post.tags else [],
                "isAnonymous": post.post_type,
                "category": {
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                },
                "user": {
                    "id": f"user_{user.id}",
                    "name": user.name
                },
                "postedTime": post.created_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating group post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error updating group post: {str(e)}")


@app.delete("/group/delete-post/{post_id}")
def delete_group_post(post_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete a group post.
    Only the post creator can delete their own post.
    Use the numeric ID (e.g., 1, 2, 3) not "post_1" format.
    """
    try:
        with Session(engine) as session:
            post = session.query(GroupPost).filter(GroupPost.id == post_id).first()
            
            if not post:
                raise HTTPException(status_code=404, detail="Group post not found")
            
            # Check if user is the creator
            if post.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to delete this post")
            
            session.delete(post)
            session.commit()
            
            return {
                "message": "Group post deleted successfully",
                "id": f"post_{post_id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting group post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error deleting group post: {str(e)}")


@app.post("/group/toggle-like/{post_id}")
def toggle_group_post_like(post_id: int, current_user: User = Depends(get_current_user)):
    """
    Like/unlike a group post.
    If the user has already liked the post, this will unlike it.
    Updates and returns the stored likeCount and hasLiked.
    """
    try:
        with Session(engine) as session:
            post = session.query(GroupPost).filter(GroupPost.id == post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Group post not found")

            existing_like = session.query(GroupPostLike).filter(
                GroupPostLike.post_id == post_id,
                GroupPostLike.user_id == current_user.id
            ).first()

            if existing_like:
                # Unlike - decrement count
                session.delete(existing_like)
                post.like_count = max(0, post.like_count - 1)  # Ensure count doesn't go below 0
                has_liked = False
            else:
                # Like - increment count
                new_like = GroupPostLike(
                    post_id=post_id,
                    user_id=current_user.id
                )
                session.add(new_like)
                post.like_count = post.like_count + 1
                has_liked = True

            session.add(post)
            session.commit()
            session.refresh(post)

            return {
                "id": f"post_{post.id}",
                "likeCount": post.like_count,
                "hasLiked": has_liked
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling like on group post: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error toggling like: {str(e)}")


@app.post("/group/comments")
def create_group_comment(data: CreateGroupCommentSchema, current_user: User = Depends(get_current_user)):
    """
    Create a comment or reply on a group post.
    """
    try:
        with Session(engine) as session:
            # Parse post ID
            try:
                if isinstance(data.postId, str) and data.postId.startswith("post_"):
                    post_id = int(data.postId.replace("post_", ""))
                else:
                    post_id = int(data.postId)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid postId format")

            post = session.query(GroupPost).filter(GroupPost.id == post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Group post not found")

            # Parent comment (for replies)
            parent_comment_id: Optional[int] = None
            if data.parentCommentId:
                try:
                    if data.parentCommentId.startswith("comment_"):
                        parent_comment_id = int(data.parentCommentId.replace("comment_", ""))
                    else:
                        parent_comment_id = int(data.parentCommentId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid parentCommentId format")

                parent = session.query(GroupComment).filter(GroupComment.id == parent_comment_id).first()
                if not parent:
                    raise HTTPException(status_code=404, detail="Parent comment not found")

            comment = GroupComment(
                post_id=post_id,
                user_id=current_user.id,
                text=data.text,
                parent_comment_id=parent_comment_id,
            )

            session.add(comment)
            session.commit()
            session.refresh(comment)

            return {
                "message": "Comment created successfully",
                "id": f"comment_{comment.id}",
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating group comment: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error creating comment: {str(e)}")


@app.get("/group/comments/{post_id}", response_model=List[ViewGroupCommentSchema])
def get_group_comments(post_id: str, current_user: User = Depends(get_current_user)):
    """
    Get comments (and replies) for a group post.
    """
    try:
        with Session(engine) as session:
            # Parse post ID
            try:
                if post_id.startswith("post_"):
                    numeric_post_id = int(post_id.replace("post_", ""))
                else:
                    numeric_post_id = int(post_id)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid postId format")

            post = session.query(GroupPost).filter(GroupPost.id == numeric_post_id).first()
            if not post:
                raise HTTPException(status_code=404, detail="Group post not found")

            comments = (
                session.query(GroupComment)
                .filter(GroupComment.post_id == numeric_post_id)
                .order_by(GroupComment.created_at.asc())
                .all()
            )

            results: List[ViewGroupCommentSchema] = []
            for c in comments:
                user = session.query(User).filter(User.id == c.user_id).first()
                if not user:
                    continue

                like_count = (
                    session.query(GroupCommentLike)
                    .filter(GroupCommentLike.comment_id == c.id)
                    .count()
                )
                has_liked = (
                    session.query(GroupCommentLike)
                    .filter(
                        GroupCommentLike.comment_id == c.id,
                        GroupCommentLike.user_id == current_user.id,
                    )
                    .first()
                    is not None
                )

                results.append(
                    ViewGroupCommentSchema(
                        id=f"comment_{c.id}",
                        postId=f"post_{c.post_id}",
                        parentCommentId=f"comment_{c.parent_comment_id}"
                        if c.parent_comment_id is not None
                        else None,
                        text=c.text,
                        user={
                            "id": f"user_{user.id}",
                            "name": user.name,
                            "role": user.role,
                        },
                        likeCount=like_count,
                        hasLiked=has_liked,
                        createdAt=c.created_at.isoformat(),
                    )
                )

            return results
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching group comments: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error fetching comments: {str(e)}")


@app.post("/group/comments/{comment_id}/toggle-like")
def toggle_group_comment_like(comment_id: int, current_user: User = Depends(get_current_user)):
    """
    Like/unlike a group comment (or reply).
    """
    try:
        with Session(engine) as session:
            comment = session.query(GroupComment).filter(GroupComment.id == comment_id).first()
            if not comment:
                raise HTTPException(status_code=404, detail="Comment not found")

            existing = session.query(GroupCommentLike).filter(
                GroupCommentLike.comment_id == comment_id,
                GroupCommentLike.user_id == current_user.id,
            ).first()

            if existing:
                session.delete(existing)
                has_liked = False
            else:
                new_like = GroupCommentLike(
                    comment_id=comment_id,
                    user_id=current_user.id,
                )
                session.add(new_like)
                has_liked = True

            session.commit()

            like_count = (
                session.query(GroupCommentLike)
                .filter(GroupCommentLike.comment_id == comment_id)
                .count()
            )

            return {
                "id": f"comment_{comment.id}",
                "likeCount": like_count,
                "hasLiked": has_liked,
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error toggling like on group comment: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error toggling like: {str(e)}")


# ==================== Contributor Profile Setup APIs ====================

@app.post("/contributor/profile/step1-basic-profile")
def create_step1_basic_profile(
    data: Step1BasicProfileSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 1: Create basic profile information.
    All fields are required. Returns error if profile already exists for this user.
    """
    try:
        with Session(engine) as session:
            # Check if profile already exists
            existing_profile = session.query(ContributorProfile).filter(
                ContributorProfile.user_id == current_user.id
            ).first()
            
            if existing_profile:
                raise HTTPException(
                    status_code=409,
                    detail="Profile already exists for this user. Cannot create duplicate profile."
                )
            
            # Create new profile
            new_profile = ContributorProfile(
                user_id=current_user.id,
                first_name=data.first_name,
                last_name=data.last_name,
                professional_title=data.professional_title,
                short_bio=data.short_bio
            )
            session.add(new_profile)
            session.commit()
            
            return {
                "message": "Step 1 profile created successfully",
                "step1_basic_profile": {
                    "first_name": data.first_name,
                    "last_name": data.last_name,
                    "professional_title": data.professional_title,
                    "short_bio": data.short_bio
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating step 1 profile: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating profile: {str(e)}")


@app.patch("/contributor/profile/step1-basic-profile")
def update_step1_basic_profile(
    data: Step1BasicProfileSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 1: Update basic profile information.
    All fields are required. Returns 404 if profile doesn't exist yet.
    """
    try:
        with Session(engine) as session:
            profile = session.query(ContributorProfile).filter(
                ContributorProfile.user_id == current_user.id
            ).first()

            if not profile:
                raise HTTPException(status_code=404, detail="Profile not found. Please complete step 1 first.")

            profile.first_name = data.first_name
            profile.last_name = data.last_name
            profile.professional_title = data.professional_title
            profile.short_bio = data.short_bio
            profile.updated_at = datetime.utcnow()

            session.add(profile)
            session.commit()
            session.refresh(profile)

            return {
                "message": "Step 1 profile updated successfully",
                "step1_basic_profile": {
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "professional_title": profile.professional_title,
                    "short_bio": profile.short_bio
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating step 1 profile: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating profile: {str(e)}")


@app.post("/contributor/profile/step2-education")
def create_step2_education(
    data: Step2EducationSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 2: Create education entries.
    All fields are required. Returns error if education_id already exists for this user.
    """
    try:
        with Session(engine) as session:
            # Check for duplicate education_ids
            existing_education_ids = {
                edu.education_id
                for edu in session.query(ContributorEducation).filter(
                    ContributorEducation.user_id == current_user.id,
                    ContributorEducation.education_id.in_([e.education_id for e in data.education])
                ).all()
            }
            
            duplicate_ids = [edu.education_id for edu in data.education if edu.education_id in existing_education_ids]
            if duplicate_ids:
                raise HTTPException(
                    status_code=409,
                    detail=f"Education entries with these IDs already exist: {', '.join(duplicate_ids)}"
                )
            
            # Create new education entries
            created_educations = []
            for edu in data.education:
                new_education = ContributorEducation(
                    user_id=current_user.id,
                    education_id=edu.education_id,
                    institution_name=edu.institution_name,
                    degree=edu.degree,
                    year_of_graduation=edu.year_of_graduation,
                    field_of_study=edu.field_of_study
                )
                session.add(new_education)
                created_educations.append({
                    "education_id": edu.education_id,
                    "institution_name": edu.institution_name,
                    "degree": edu.degree,
                    "year_of_graduation": edu.year_of_graduation,
                    "field_of_study": edu.field_of_study
                })
            
            session.commit()
            
            return {
                "message": "Step 2 education created successfully",
                "step2_education": created_educations
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating step 2 education: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating education: {str(e)}")


@app.patch("/contributor/profile/step2-education")
def update_step2_education(
    data: Step2EducationSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 2: Update education entries (replace-all).
    All fields are required. Replaces the user's entire education list.
    """
    try:
        incoming_ids = [e.education_id for e in data.education]
        if len(incoming_ids) != len(set(incoming_ids)):
            raise HTTPException(status_code=400, detail="Duplicate education_id found in request body.")

        with Session(engine) as session:
            # Replace-all behavior: delete existing, then insert incoming list
            session.query(ContributorEducation).filter(
                ContributorEducation.user_id == current_user.id
            ).delete(synchronize_session=False)

            created_educations = []
            for edu in data.education:
                new_education = ContributorEducation(
                    user_id=current_user.id,
                    education_id=edu.education_id,
                    institution_name=edu.institution_name,
                    degree=edu.degree,
                    year_of_graduation=edu.year_of_graduation,
                    field_of_study=edu.field_of_study
                )
                session.add(new_education)
                created_educations.append({
                    "education_id": edu.education_id,
                    "institution_name": edu.institution_name,
                    "degree": edu.degree,
                    "year_of_graduation": edu.year_of_graduation,
                    "field_of_study": edu.field_of_study
                })

            session.commit()

            return {
                "message": "Step 2 education updated successfully",
                "step2_education": created_educations
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating step 2 education: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating education: {str(e)}")


@app.post("/contributor/profile/step3-experience")
def create_step3_experience(
    data: Step3ExperienceSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 3: Create work experience entries.
    All fields are required. Returns error if experience_id already exists for this user.
    """
    try:
        with Session(engine) as session:
            # Check for duplicate experience_ids
            existing_experience_ids = {
                exp.experience_id
                for exp in session.query(ContributorExperience).filter(
                    ContributorExperience.user_id == current_user.id,
                    ContributorExperience.experience_id.in_([e.experience_id for e in data.experience])
                ).all()
            }
            
            duplicate_ids = [exp.experience_id for exp in data.experience if exp.experience_id in existing_experience_ids]
            if duplicate_ids:
                raise HTTPException(
                    status_code=409,
                    detail=f"Experience entries with these IDs already exist: {', '.join(duplicate_ids)}"
                )
            
            # Create new experience entries
            created_experiences = []
            for exp in data.experience:
                new_experience = ContributorExperience(
                    user_id=current_user.id,
                    experience_id=exp.experience_id,
                    job_title=exp.job_title,
                    company_name=exp.company_name,
                    start_month=exp.start_month,
                    start_year=exp.start_year,
                    end_month=exp.end_month,
                    end_year=exp.end_year,
                    is_currently_working=exp.is_currently_working,
                    key_responsibilities=exp.key_responsibilities
                )
                session.add(new_experience)
                created_experiences.append({
                    "experience_id": exp.experience_id,
                    "job_title": exp.job_title,
                    "company_name": exp.company_name,
                    "start_month": exp.start_month,
                    "start_year": exp.start_year,
                    "end_month": exp.end_month,
                    "end_year": exp.end_year,
                    "is_currently_working": exp.is_currently_working,
                    "key_responsibilities": exp.key_responsibilities
                })
            
            session.commit()
            
            return {
                "message": "Step 3 experience created successfully",
                "step3_experience": created_experiences
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating step 3 experience: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating experience: {str(e)}")


@app.patch("/contributor/profile/step3-experience")
def update_step3_experience(
    data: Step3ExperienceSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 3: Update work experience entries (replace-all).
    All fields are required. Replaces the user's entire experience list.
    """
    try:
        incoming_ids = [e.experience_id for e in data.experience]
        if len(incoming_ids) != len(set(incoming_ids)):
            raise HTTPException(status_code=400, detail="Duplicate experience_id found in request body.")

        with Session(engine) as session:
            session.query(ContributorExperience).filter(
                ContributorExperience.user_id == current_user.id
            ).delete(synchronize_session=False)

            created_experiences = []
            for exp in data.experience:
                new_experience = ContributorExperience(
                    user_id=current_user.id,
                    experience_id=exp.experience_id,
                    job_title=exp.job_title,
                    company_name=exp.company_name,
                    start_month=exp.start_month,
                    start_year=exp.start_year,
                    end_month=exp.end_month,
                    end_year=exp.end_year,
                    is_currently_working=exp.is_currently_working,
                    key_responsibilities=exp.key_responsibilities
                )
                session.add(new_experience)
                created_experiences.append({
                    "experience_id": exp.experience_id,
                    "job_title": exp.job_title,
                    "company_name": exp.company_name,
                    "start_month": exp.start_month,
                    "start_year": exp.start_year,
                    "end_month": exp.end_month,
                    "end_year": exp.end_year,
                    "is_currently_working": exp.is_currently_working,
                    "key_responsibilities": exp.key_responsibilities
                })

            session.commit()

            return {
                "message": "Step 3 experience updated successfully",
                "step3_experience": created_experiences
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating step 3 experience: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating experience: {str(e)}")


@app.post("/contributor/profile/step4-certifications")
def create_step4_certifications(
    data: Step4CertificationsSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 4: Create certification entries.
    All fields are required (except expiration_date and credential_id which can be null).
    Returns error if certification_id already exists for this user.
    """
    try:
        with Session(engine) as session:
            # Check for duplicate certification_ids
            existing_certification_ids = {
                cert.certification_id
                for cert in session.query(ContributorCertification).filter(
                    ContributorCertification.user_id == current_user.id,
                    ContributorCertification.certification_id.in_([c.certification_id for c in data.certifications])
                ).all()
            }
            
            duplicate_ids = [cert.certification_id for cert in data.certifications if cert.certification_id in existing_certification_ids]
            if duplicate_ids:
                raise HTTPException(
                    status_code=409,
                    detail=f"Certification entries with these IDs already exist: {', '.join(duplicate_ids)}"
                )
            
            # Create new certification entries
            created_certifications = []
            for cert in data.certifications:
                # Parse date_issued (handle various ISO formats)
                date_issued_str = cert.date_issued
                if date_issued_str.endswith('Z'):
                    date_issued_str = date_issued_str.replace('Z', '+00:00')
                elif '+' not in date_issued_str and 'T' in date_issued_str:
                    date_issued_str = date_issued_str + '+00:00'
                date_issued = datetime.fromisoformat(date_issued_str)
                
                expiration_date = None
                if cert.expiration_date:
                    exp_date_str = cert.expiration_date
                    if exp_date_str.endswith('Z'):
                        exp_date_str = exp_date_str.replace('Z', '+00:00')
                    elif '+' not in exp_date_str and 'T' in exp_date_str:
                        exp_date_str = exp_date_str + '+00:00'
                    expiration_date = datetime.fromisoformat(exp_date_str)
                
                new_certification = ContributorCertification(
                    user_id=current_user.id,
                    certification_id=cert.certification_id,
                    certification_name=cert.certification_name,
                    issuing_organization=cert.issuing_organization,
                    date_issued=date_issued,
                    expiration_date=expiration_date,
                    credential_id=cert.credential_id
                )
                session.add(new_certification)
                created_certifications.append({
                    "certification_id": cert.certification_id,
                    "certification_name": cert.certification_name,
                    "issuing_organization": cert.issuing_organization,
                    "date_issued": cert.date_issued,
                    "expiration_date": cert.expiration_date,
                    "credential_id": cert.credential_id
                })
            
            session.commit()
            
            return {
                "message": "Step 4 certifications created successfully",
                "step4_certifications": created_certifications
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating step 4 certifications: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating certifications: {str(e)}")


@app.patch("/contributor/profile/step4-certifications")
def update_step4_certifications(
    data: Step4CertificationsSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 4: Update certification entries (replace-all).
    All fields are required (except expiration_date and credential_id which can be null).
    Replaces the user's entire certifications list.
    """
    try:
        incoming_ids = [c.certification_id for c in data.certifications]
        if len(incoming_ids) != len(set(incoming_ids)):
            raise HTTPException(status_code=400, detail="Duplicate certification_id found in request body.")

        with Session(engine) as session:
            session.query(ContributorCertification).filter(
                ContributorCertification.user_id == current_user.id
            ).delete(synchronize_session=False)

            created_certifications = []
            for cert in data.certifications:
                # Parse date_issued (handle various ISO formats)
                date_issued_str = cert.date_issued
                if date_issued_str.endswith('Z'):
                    date_issued_str = date_issued_str.replace('Z', '+00:00')
                elif '+' not in date_issued_str and 'T' in date_issued_str:
                    date_issued_str = date_issued_str + '+00:00'
                date_issued = datetime.fromisoformat(date_issued_str)

                expiration_date = None
                if cert.expiration_date:
                    exp_date_str = cert.expiration_date
                    if exp_date_str.endswith('Z'):
                        exp_date_str = exp_date_str.replace('Z', '+00:00')
                    elif '+' not in exp_date_str and 'T' in exp_date_str:
                        exp_date_str = exp_date_str + '+00:00'
                    expiration_date = datetime.fromisoformat(exp_date_str)

                new_certification = ContributorCertification(
                    user_id=current_user.id,
                    certification_id=cert.certification_id,
                    certification_name=cert.certification_name,
                    issuing_organization=cert.issuing_organization,
                    date_issued=date_issued,
                    expiration_date=expiration_date,
                    credential_id=cert.credential_id
                )
                session.add(new_certification)
                created_certifications.append({
                    "certification_id": cert.certification_id,
                    "certification_name": cert.certification_name,
                    "issuing_organization": cert.issuing_organization,
                    "date_issued": cert.date_issued,
                    "expiration_date": cert.expiration_date,
                    "credential_id": cert.credential_id
                })

            session.commit()

            return {
                "message": "Step 4 certifications updated successfully",
                "step4_certifications": created_certifications
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating step 4 certifications: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating certifications: {str(e)}")


@app.post("/contributor/profile/step5-expertise-and-publications")
def create_step5_expertise_and_publications(
    data: Step5ExpertiseAndPublicationsSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 5: Create expertise topics and publications.
    All fields are required. Returns error if publication_id already exists for this user.
    Note: Expertise topics can have duplicates (same topic can be added multiple times).
    """
    try:
        with Session(engine) as session:
            # Check for duplicate publication_ids
            existing_publication_ids = {
                pub.publication_id
                for pub in session.query(ContributorPublication).filter(
                    ContributorPublication.user_id == current_user.id,
                    ContributorPublication.publication_id.in_([p.publication_id for p in data.publications])
                ).all()
            }
            
            duplicate_ids = [pub.publication_id for pub in data.publications if pub.publication_id in existing_publication_ids]
            if duplicate_ids:
                raise HTTPException(
                    status_code=409,
                    detail=f"Publication entries with these IDs already exist: {', '.join(duplicate_ids)}"
                )
            
            # Create new expertise entries (duplicates allowed for expertise topics)
            for topic in data.expertise_topics:
                new_expertise = ContributorExpertise(
                    user_id=current_user.id,
                    topic=topic
                )
                session.add(new_expertise)
            
            # Create new publication entries
            created_publications = []
            for pub in data.publications:
                new_publication = ContributorPublication(
                    user_id=current_user.id,
                    publication_id=pub.publication_id,
                    title=pub.title,
                    url=pub.url
                )
                session.add(new_publication)
                created_publications.append({
                    "publication_id": pub.publication_id,
                    "title": pub.title,
                    "url": pub.url
                })
            
            session.commit()
            
            return {
                "message": "Step 5 expertise and publications created successfully",
                "step5_expertise_and_publications": {
                    "expertise_topics": data.expertise_topics,
                    "publications": created_publications
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating step 5 expertise and publications: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating expertise and publications: {str(e)}")


@app.patch("/contributor/profile/step5-expertise-and-publications")
def update_step5_expertise_and_publications(
    data: Step5ExpertiseAndPublicationsSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Step 5: Update expertise topics and publications (replace-all).
    Expertise topics can contain duplicates. Publications require unique publication_id values.
    """
    try:
        incoming_pub_ids = [p.publication_id for p in data.publications]
        if len(incoming_pub_ids) != len(set(incoming_pub_ids)):
            raise HTTPException(status_code=400, detail="Duplicate publication_id found in request body.")

        with Session(engine) as session:
            # Replace-all: remove existing topics + publications, then insert incoming
            session.query(ContributorExpertise).filter(
                ContributorExpertise.user_id == current_user.id
            ).delete(synchronize_session=False)
            session.query(ContributorPublication).filter(
                ContributorPublication.user_id == current_user.id
            ).delete(synchronize_session=False)

            for topic in data.expertise_topics:
                session.add(ContributorExpertise(user_id=current_user.id, topic=topic))

            created_publications = []
            for pub in data.publications:
                session.add(ContributorPublication(
                    user_id=current_user.id,
                    publication_id=pub.publication_id,
                    title=pub.title,
                    url=pub.url
                ))
                created_publications.append({
                    "publication_id": pub.publication_id,
                    "title": pub.title,
                    "url": pub.url
                })

            session.commit()

            return {
                "message": "Step 5 expertise and publications updated successfully",
                "step5_expertise_and_publications": {
                    "expertise_topics": data.expertise_topics,
                    "publications": created_publications
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating step 5 expertise and publications: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating expertise and publications: {str(e)}")


@app.get("/contributor/profile", response_model=ContributorProfileResponseSchema)
def get_contributor_profile(current_user: User = Depends(get_current_user)):
    """
    Get all profile information for the current user (all 5 steps).
    Returns empty arrays/None for steps that haven't been completed yet.
    """
    try:
        with Session(engine) as session:
            # Step 1: Basic Profile
            profile = session.query(ContributorProfile).filter(
                ContributorProfile.user_id == current_user.id
            ).first()
            
            step1_data = None
            if profile:
                step1_data = {
                    "first_name": profile.first_name,
                    "last_name": profile.last_name,
                    "professional_title": profile.professional_title,
                    "short_bio": profile.short_bio
                }
            
            # Step 2: Education
            education_list = session.query(ContributorEducation).filter(
                ContributorEducation.user_id == current_user.id
            ).all()
            
            step2_data = [
                {
                    "education_id": edu.education_id,
                    "institution_name": edu.institution_name,
                    "degree": edu.degree,
                    "year_of_graduation": edu.year_of_graduation,
                    "field_of_study": edu.field_of_study
                }
                for edu in education_list
            ]
            
            # Step 3: Experience
            experience_list = session.query(ContributorExperience).filter(
                ContributorExperience.user_id == current_user.id
            ).all()
            
            step3_data = [
                {
                    "experience_id": exp.experience_id,
                    "job_title": exp.job_title,
                    "company_name": exp.company_name,
                    "start_month": exp.start_month,
                    "start_year": exp.start_year,
                    "end_month": exp.end_month,
                    "end_year": exp.end_year,
                    "is_currently_working": exp.is_currently_working,
                    "key_responsibilities": exp.key_responsibilities
                }
                for exp in experience_list
            ]
            
            # Step 4: Certifications
            certification_list = session.query(ContributorCertification).filter(
                ContributorCertification.user_id == current_user.id
            ).all()
            
            step4_data = [
                {
                    "certification_id": cert.certification_id,
                    "certification_name": cert.certification_name,
                    "issuing_organization": cert.issuing_organization,
                    "date_issued": cert.date_issued.isoformat(),
                    "expiration_date": cert.expiration_date.isoformat() if cert.expiration_date else None,
                    "credential_id": cert.credential_id
                }
                for cert in certification_list
            ]
            
            # Step 5: Expertise and Publications
            expertise_list = session.query(ContributorExpertise).filter(
                ContributorExpertise.user_id == current_user.id
            ).all()
            
            publication_list = session.query(ContributorPublication).filter(
                ContributorPublication.user_id == current_user.id
            ).all()
            
            step5_data = None
            if expertise_list or publication_list:
                step5_data = {
                    "expertise_topics": [exp.topic for exp in expertise_list],
                    "publications": [
                        {
                            "publication_id": pub.publication_id,
                            "title": pub.title,
                            "url": pub.url
                        }
                        for pub in publication_list
                    ]
                }
            
            return {
                "step1_basic_profile": step1_data,
                "step2_education": step2_data,
                "step3_experience": step3_data,
                "step4_certifications": step4_data,
                "step5_expertise_and_publications": step5_data
            }
    except Exception as e:
        logger.error(f"Error fetching contributor profile: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching profile: {str(e)}")


# ==================== Contributor Article APIs ====================

@app.post("/contributor/article/upload-image")
async def upload_article_image(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Upload images for contributor articles.
    Returns the image URL to be used in the create-article API's image field.
    Uses Supabase Storage in production, local storage in development.
    """
    try:
        # Validate file type (images only)
        if not file.content_type or not file.content_type.startswith('image/'):
            raise HTTPException(status_code=400, detail="File must be an image")
        
        # Generate unique filename
        file_extension = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{current_user.id}{file_extension}"
        
        # Read file content
        content = await file.read()
        
        # Determine storage path
        storage_folder = "article-images"
        storage_key = f"{storage_folder}/{unique_filename}"
        
        # Use Supabase Storage if configured, otherwise use local storage
        if supabase_client and USE_SUPABASE_STORAGE:
            # Upload to Supabase Storage
            try:
                # Upload file to Supabase Storage
                response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).upload(
                    path=storage_key,
                    file=content,
                    file_options={"content-type": file.content_type, "upsert": "true"}
                )
                
                # Get public URL
                public_url_response = supabase_client.storage.from_(SUPABASE_STORAGE_BUCKET).get_public_url(storage_key)
                public_url = public_url_response
                
                logger.info(f"Article image uploaded to Supabase Storage: {storage_key}")
                
                return {
                    "url": public_url  # Return URL to use in create-article API
                }
            except Exception as e:
                logger.error(f"Supabase Storage upload error: {str(e)}", exc_info=True)
                raise HTTPException(status_code=503, detail=f"Error uploading to Supabase Storage: {str(e)}")
        else:
            # Local storage fallback (for development)
            upload_dir = os.path.join("uploads", storage_folder)
            os.makedirs(upload_dir, exist_ok=True)
            
            file_path = os.path.join(upload_dir, unique_filename)
            
            # Save file locally
            with open(file_path, "wb") as buffer:
                buffer.write(content)
            
            logger.info(f"Article image saved locally: {file_path}")
            
            return {
                "url": f"/uploads/{storage_key}"  # Relative URL for local files
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading article image: {str(e)}", exc_info=True)
        raise HTTPException(status_code=503, detail=f"Error uploading image: {str(e)}")


@app.post("/contributor/article/create")
def create_article(data: CreateArticleSchema, current_user: User = Depends(get_current_user)):
    """
    Create a new article by contributor.
    All fields are required: title, preview, content, image, tags, categoryId.
    """
    try:
        with Session(engine) as session:
            # Validate category exists
            # Handle categoryId as "cat_001" format or integer
            category_id = None
            if data.categoryId.startswith("cat_"):
                try:
                    category_id = int(data.categoryId.replace("cat_", ""))
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            else:
                try:
                    category_id = int(data.categoryId)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid categoryId format")
            
            category = session.query(Category).filter(Category.id == category_id).first()
            if not category:
                raise HTTPException(status_code=404, detail="Category not found")
            
            # Create new article
            new_article = Article(
                title=data.title,
                preview=data.preview,
                content=data.content,
                image=data.image,
                tags=json.dumps(data.tags),
                category_id=category_id,
                user_id=current_user.id
            )
            
            session.add(new_article)
            session.commit()
            session.refresh(new_article)
            
            return {
                "message": "Article created successfully",
                "id": f"article_{new_article.id}",
                "title": new_article.title,
                "preview": new_article.preview,
                "content": new_article.content,
                "image": new_article.image,
                "tags": json.loads(new_article.tags) if new_article.tags else [],
                "category": {
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                },
                "status": new_article.status,
                "like_count": new_article.like_count,
                "createdAt": new_article.created_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating article: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating article: {str(e)}")


@app.patch("/contributor/article/update/{article_id}")
def update_article(
    article_id: int,
    article_data: UpdateArticleSchema,
    current_user: User = Depends(get_current_user)
):
    """
    Update an existing article.
    Only the article creator can update their own article.
    Use the numeric ID (e.g., 1, 2, 3) not "article_1" format.
    All fields are optional - only provided fields will be updated.
    """
    try:
        with Session(engine) as session:
            article = session.query(Article).filter(Article.id == article_id).first()
            
            if not article:
                raise HTTPException(status_code=404, detail="Article not found")
            
            # Check if user is the creator
            if article.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to edit this article")
            
            # Update fields if provided
            if article_data.title is not None:
                article.title = article_data.title
            if article_data.preview is not None:
                article.preview = article_data.preview
            if article_data.content is not None:
                article.content = article_data.content
            if article_data.image is not None:
                article.image = article_data.image
            if article_data.tags is not None:
                article.tags = json.dumps(article_data.tags)
            if article_data.categoryId is not None:
                # Validate category exists
                category_id = None
                if article_data.categoryId.startswith("cat_"):
                    try:
                        category_id = int(article_data.categoryId.replace("cat_", ""))
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                else:
                    try:
                        category_id = int(article_data.categoryId)
                    except ValueError:
                        raise HTTPException(status_code=400, detail="Invalid categoryId format")
                
                category = session.query(Category).filter(Category.id == category_id).first()
                if not category:
                    raise HTTPException(status_code=404, detail="Category not found")
                
                article.category_id = category_id
            
            # Update updated_at timestamp
            article.updated_at = datetime.utcnow()
            
            session.add(article)
            session.commit()
            session.refresh(article)
            
            # Get category info for response
            category = session.query(Category).filter(Category.id == article.category_id).first()
            
            return {
                "message": "Article updated successfully",
                "id": f"article_{article.id}",
                "title": article.title,
                "preview": article.preview,
                "content": article.content,
                "image": article.image,
                "tags": json.loads(article.tags) if article.tags else [],
                "category": {
                    "id": f"cat_{category.id:03d}",
                    "name": category.name
                },
                "status": article.status,
                "like_count": article.like_count,
                "updatedAt": article.updated_at.isoformat()
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating article: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error updating article: {str(e)}")


@app.delete("/contributor/article/{article_id}")
def delete_article(article_id: int, current_user: User = Depends(get_current_user)):
    """
    Delete an article.
    Only the article creator can delete their own article.
    Use the numeric ID (e.g., 1, 2, 3) not "article_1" format.
    """
    try:
        with Session(engine) as session:
            article = session.query(Article).filter(Article.id == article_id).first()
            
            if not article:
                raise HTTPException(status_code=404, detail="Article not found")
            
            # Check if user is the creator
            if article.user_id != current_user.id:
                raise HTTPException(status_code=403, detail="You don't have permission to delete this article")
            
            session.delete(article)
            session.commit()
            
            return {
                "message": "Article deleted successfully",
                "id": f"article_{article_id}"
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting article: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error deleting article: {str(e)}")


# ==================== Helper Function for Admin Check ====================

def get_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Helper function to verify user is admin"""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ==================== Contributor Article Stats & List APIs ====================

@app.get("/contributor/article/stats")
def get_contributor_article_stats(current_user: User = Depends(get_current_user)):
    """
    Get article statistics for the current contributor.
    Returns: total count, published count, pending count, and total like count.
    """
    try:
        with Session(engine) as session:
            # Get all articles for this user
            all_articles = session.query(Article).filter(Article.user_id == current_user.id).all()
            
            total_count = len(all_articles)
            published_count = len([a for a in all_articles if a.status == "published"])
            pending_count = len([a for a in all_articles if a.status == "pending"])
            total_like_count = sum(a.like_count for a in all_articles)
            
            return {
                "total_article_count": total_count,
                "published_article_count": published_count,
                "pending_article_count": pending_count,
                "total_like_count": total_like_count
            }
    except Exception as e:
        logger.error(f"Error fetching article stats: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching article stats: {str(e)}")


@app.get("/contributor/article/list")
def get_contributor_article_list(current_user: User = Depends(get_current_user)):
    """
    Get all articles for the current contributor (both pending and published).
    Includes status and like_count for each article.
    """
    try:
        with Session(engine) as session:
            articles = session.query(Article).filter(
                Article.user_id == current_user.id
            ).order_by(Article.created_at.desc()).all()
            
            article_list = []
            for article in articles:
                category = session.query(Category).filter(Category.id == article.category_id).first()
                article_list.append({
                    "id": f"article_{article.id}",
                    "title": article.title,
                    "preview": article.preview,
                    "content": article.content,
                    "image": article.image,
                    "tags": json.loads(article.tags) if article.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}" if category else None,
                        "name": category.name if category else None
                    },
                    "contributor": {
                        "id": current_user.id,
                        "name": current_user.name
                    },
                    "status": article.status,
                    "like_count": article.like_count,
                    "createdAt": article.created_at.isoformat(),
                    "publishedAt": article.published_at.isoformat() if article.published_at else None
                })
            
            return article_list
    except Exception as e:
        logger.error(f"Error fetching article list: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching article list: {str(e)}")


@app.get("/contributor/article/published")
def get_contributor_published_articles(current_user: User = Depends(get_current_user)):
    """
    Get only published articles for the current contributor.
    Includes content, contributor info, and like_count for each article.
    """
    try:
        with Session(engine) as session:
            articles = session.query(Article).filter(
                Article.user_id == current_user.id,
                Article.status == "published"
            ).order_by(Article.created_at.desc()).all()
            
            article_list = []
            for article in articles:
                category = session.query(Category).filter(Category.id == article.category_id).first()
                article_list.append({
                    "id": f"article_{article.id}",
                    "title": article.title,
                    "preview": article.preview,
                    "content": article.content,
                    "image": article.image,
                    "tags": json.loads(article.tags) if article.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}" if category else None,
                        "name": category.name if category else None
                    },
                    "contributor": {
                        "id": current_user.id,
                        "name": current_user.name
                    },
                    "status": article.status,
                    "like_count": article.like_count,
                    "createdAt": article.created_at.isoformat(),
                    "publishedAt": article.published_at.isoformat() if article.published_at else None
                })
            
            return article_list
    except Exception as e:
        logger.error(f"Error fetching published articles: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching published articles: {str(e)}")


# ==================== Admin Article APIs ====================

@app.get("/admin/article/pending")
def get_pending_articles(admin_user: User = Depends(get_admin_user)):
    """
    Get all pending articles for admin review.
    Admin access required.
    """
    try:
        with Session(engine) as session:
            articles = session.query(Article).filter(
                Article.status == "pending"
            ).order_by(Article.created_at.desc()).all()
            
            article_list = []
            for article in articles:
                category = session.query(Category).filter(Category.id == article.category_id).first()
                contributor = session.query(User).filter(User.id == article.user_id).first()
                article_list.append({
                    "id": f"article_{article.id}",
                    "title": article.title,
                    "preview": article.preview,
                    "content": article.content,
                    "image": article.image,
                    "tags": json.loads(article.tags) if article.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}" if category else None,
                        "name": category.name if category else None
                    },
                    "contributor": {
                        "id": contributor.id if contributor else None,
                        "name": contributor.name if contributor else None,
                        "email": contributor.email if contributor else None
                    },
                    "status": article.status,
                    "like_count": article.like_count,
                    "createdAt": article.created_at.isoformat()
                })
            
            return article_list
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pending articles: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching pending articles: {str(e)}")


@app.patch("/admin/article/{article_id}/publish")
def publish_article(article_id: int, admin_user: User = Depends(get_admin_user)):
    """
    Publish an article (change status from "pending" to "published").
    Sets published_at timestamp.
    Admin access required.
    Use the numeric ID (e.g., 1, 2, 3) not "article_1" format.
    """
    try:
        with Session(engine) as session:
            article = session.query(Article).filter(Article.id == article_id).first()
            
            if not article:
                raise HTTPException(status_code=404, detail="Article not found")
            
            if article.status == "published":
                raise HTTPException(status_code=400, detail="Article is already published")
            
            # Update status and published_at
            article.status = "published"
            article.published_at = datetime.utcnow()
            article.updated_at = datetime.utcnow()
            
            session.add(article)
            session.commit()
            session.refresh(article)
            
            category = session.query(Category).filter(Category.id == article.category_id).first()
            
            return {
                "message": "Article published successfully",
                "id": f"article_{article.id}",
                "title": article.title,
                "status": article.status,
                "publishedAt": article.published_at.isoformat(),
                "category": {
                    "id": f"cat_{category.id:03d}" if category else None,
                    "name": category.name if category else None
                }
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error publishing article: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error publishing article: {str(e)}")


# ==================== Public Article API ====================

@app.get("/article/published")
def get_published_articles(limit: int = Query(20, ge=1, le=100)):
    """
    Get all published articles for public display.
    Public endpoint (no authentication required).
    """
    try:
        with Session(engine) as session:
            articles = session.query(Article).filter(
                Article.status == "published"
            ).order_by(Article.published_at.desc()).limit(limit).all()
            
            article_list = []
            for article in articles:
                category = session.query(Category).filter(Category.id == article.category_id).first()
                contributor = session.query(User).filter(User.id == article.user_id).first()
                article_list.append({
                    "id": f"article_{article.id}",
                    "title": article.title,
                    "preview": article.preview,
                    "content": article.content,
                    "image": article.image,
                    "tags": json.loads(article.tags) if article.tags else [],
                    "category": {
                        "id": f"cat_{category.id:03d}" if category else None,
                        "name": category.name if category else None
                    },
                    "contributor": {
                        "id": contributor.id if contributor else None,
                        "name": contributor.name if contributor else None
                    },
                    "like_count": article.like_count,
                    "publishedAt": article.published_at.isoformat() if article.published_at else None,
                    "createdAt": article.created_at.isoformat()
                })
            
            return article_list
    except Exception as e:
        logger.error(f"Error fetching published articles: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error fetching published articles: {str(e)}")