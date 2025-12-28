from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import hashlib
import logging
import os
from typing import Optional

from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
import json
from fastapi import Depends, FastAPI, HTTPException, BackgroundTasks
import firebase_admin
from firebase_admin import credentials, auth
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session

from database import init_db, engine
from models import User, EPDSResult
from schemas import SignupSchema, LoginSchema, ChangePasswordSchema, ForgotPasswordSchema, ResetPasswordSchema, UpdateNameSchema, EPDSAnswerSchema

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
                    "name": new_user.name
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
                "access_token": access_token,
                "token_type": "bearer",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": user.name
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