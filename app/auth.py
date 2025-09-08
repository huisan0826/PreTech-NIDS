# app/auth.py
from fastapi import APIRouter, HTTPException, Depends, status, Response, Request, File, UploadFile
from pydantic import BaseModel, EmailStr, validator
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from app.timezone_utils import get_beijing_time, get_beijing_time_iso
from typing import Optional
import secrets
import re
from fastapi.responses import JSONResponse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
import os
from dotenv import load_dotenv
import base64
import requests

# Load environment variables from .env if present
load_dotenv()
import shutil
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

router = APIRouter()

# MongoDB connection (use env var if provided)
client = MongoClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client["PreTectNIDS"]
users_collection = db["users"]
password_reset_collection = db["password_resets"]
password_reset_collection = db["password_resets"]
registration_verifications_collection = db["registration_verifications"]

# Simple email test endpoint
@router.post("/email/send-test")
def email_send_test(payload: dict):
    try:
        to_email = payload.get("to")
        if not to_email:
            raise HTTPException(status_code=400, detail="Email address required")
        
        msg = MIMEMultipart()
        msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
        msg['Reply-To'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = "PreTech-NIDS SMTP Test"
        body = f"""
This is a test email from PreTech-NIDS.

Server: {SMTP_SERVER}:{SMTP_PORT} SSL={SMTP_USE_SSL}
From: {FROM_EMAIL}
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        _smtp_send_message(msg, to_email)
        return {"message": "Test email sent successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send test email: {str(e)}")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = secrets.token_urlsafe(32)  # In production, use environment variable
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Email settings (you can configure these in environment variables)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.sendgrid.net")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "apikey")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")
FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@pretect-nids.com")
FROM_NAME = os.getenv("FROM_NAME", "Pre-Tech NIDS")
EMAIL_DEV_MODE = os.getenv("EMAIL_DEV_MODE", "false").lower() in ("1", "true", "yes")
SMTP_AUTH_METHOD = os.getenv("SMTP_AUTH_METHOD", "USERPASS").upper()  # USERPASS or OAUTH2
OAUTH_PROVIDER = os.getenv("OAUTH_PROVIDER", "GOOGLE").upper()        # GOOGLE or MICROSOFT
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET", "")
OAUTH_REFRESH_TOKEN = os.getenv("OAUTH_REFRESH_TOKEN", "")
OAUTH_TENANT = os.getenv("OAUTH_TENANT", "common")
OAUTH_TOKEN_URI = os.getenv("OAUTH_TOKEN_URI", "")
OAUTH_SCOPE = os.getenv("OAUTH_SCOPE", "")

# ---- Email configuration logging helpers ----
def _mask_email(value: str) -> str:
    try:
        if not value:
            return ""
        if "@" not in value:
            return value[:2] + "***"
        name, domain = value.split("@", 1)
        visible = name[:2] if len(name) >= 2 else name
        return f"{visible}***@{domain}"
    except Exception:
        return "***"

def get_email_config_summary() -> dict:
    provider = ("SendGrid" if SMTP_SERVER == "smtp.sendgrid.net" and SMTP_USERNAME == "apikey" else OAUTH_PROVIDER)
    return {
        "auth_method": SMTP_AUTH_METHOD,
        "provider": provider,
        "server": SMTP_SERVER,
        "port": SMTP_PORT,
        "use_ssl": SMTP_USE_SSL,
        "username_masked": _mask_email(SMTP_USERNAME),
        "from_email": FROM_EMAIL,
        "dev_mode": EMAIL_DEV_MODE,
    }

# Log a concise, non-sensitive summary at import time
try:
    summary = get_email_config_summary()
    print(
        f"[EmailConfig] mode={summary['auth_method']} provider={summary['provider']} "
        f"server={summary['server']}:{summary['port']} ssl={summary['use_ssl']} "
        f"user={summary['username_masked']} from={summary['from_email']} dev={summary['dev_mode']}"
    )
except Exception:
    pass

def _get_oauth2_access_token() -> str:
    """Obtain OAuth2 access token using refresh token for Gmail or Microsoft 365."""
    if not OAUTH_CLIENT_ID or not OAUTH_CLIENT_SECRET or not OAUTH_REFRESH_TOKEN:
        raise RuntimeError("Missing OAuth2 credentials: OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET / OAUTH_REFRESH_TOKEN")

    if OAUTH_PROVIDER == "GOOGLE":
        token_uri = OAUTH_TOKEN_URI or "https://oauth2.googleapis.com/token"
        data = {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "refresh_token": OAUTH_REFRESH_TOKEN,
            "grant_type": "refresh_token"
        }
        resp = requests.post(token_uri, data=data, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Google OAuth token failed: {resp.status_code} {resp.text}")
        return resp.json().get("access_token")
    elif OAUTH_PROVIDER == "MICROSOFT":
        token_uri = OAUTH_TOKEN_URI or f"https://login.microsoftonline.com/{OAUTH_TENANT}/oauth2/v2.0/token"
        scope = OAUTH_SCOPE or "https://outlook.office365.com/.default offline_access"
        data = {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
            "refresh_token": OAUTH_REFRESH_TOKEN,
            "grant_type": "refresh_token",
            "scope": scope
        }
        resp = requests.post(token_uri, data=data, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"Microsoft OAuth token failed: {resp.status_code} {resp.text}")
        return resp.json().get("access_token")
    else:
        raise RuntimeError(f"Unsupported OAUTH_PROVIDER: {OAUTH_PROVIDER}")


def _smtp_send_message(msg: MIMEMultipart, to_email: str):
    """Send email via SMTP using USERPASS or XOAUTH2 depending on config."""
    if SMTP_USE_SSL or SMTP_PORT == 465:
        server = smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT, timeout=20)
    else:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20)
        server.ehlo()
        server.starttls()
        server.ehlo()

    try:
        if SMTP_AUTH_METHOD == "OAUTH2":
            access_token = _get_oauth2_access_token()
            if not access_token:
                raise RuntimeError("Failed to obtain OAuth2 access token")
            auth_str = f"user={SMTP_USERNAME}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
            auth_b64 = base64.b64encode(auth_str).decode("utf-8")
            code, resp = server.docmd("AUTH", "XOAUTH2 " + auth_b64)
            if code != 235:
                raise RuntimeError(f"SMTP XOAUTH2 auth failed: {code} {resp}")
        else:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)

        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
    finally:
        try:
            server.quit()
        except Exception:
            pass

# Avatar upload settings
AVATAR_UPLOAD_DIR = Path("uploads/avatars")
AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_IMAGE_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"]
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5MB

# Role and Permission System
class UserRole:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @classmethod
    def get_all_roles(cls):
        return [cls.ADMIN, cls.ANALYST, cls.VIEWER]

    @classmethod
    def get_role_permissions(cls, role):
        """Get permissions for a specific role"""
        permissions = {
            cls.ADMIN: [
                "user_management",
                "system_settings",
                "view_reports",
                "manual_testing",
                "real_time_detection",
                "export_data",
                "delete_reports",
                "pcap_analysis",
                "alert_management",
                "view_alerts",
                "network_security"
            ],
            cls.ANALYST: [
                "view_reports",
                "manual_testing",
                "real_time_detection",
                "export_data",
                "pcap_analysis",
                "view_alerts",
                "network_security"
            ],
            cls.VIEWER: [
                "view_reports",
                "view_alerts"
            ]
        }
        return permissions.get(role, [])

    @classmethod
    def get_role_display_name(cls, role):
        """Get display name for role"""
        display_names = {
            cls.ADMIN: "System Administrator",
            cls.ANALYST: "Security Analyst",
            cls.VIEWER: "Report Viewer"
        }
        return display_names.get(role, "Unknown Role")

def get_default_role() -> str:
    return UserRole.VIEWER

def has_permission(user_role: str, permission: str) -> bool:
    """Check if a user role has a specific permission"""
    return permission in UserRole.get_role_permissions(user_role)

def extract_token_from_request(request: Request) -> str:
    """Extract and clean JWT token from request cookies"""
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="No access token")
    
    # Remove "Bearer " prefix if present
    if token.startswith("Bearer "):
        token = token[7:]
    
    return token

async def get_current_user_from_request(request: Request):
    """Get current user from request token"""
    token = extract_token_from_request(request)
    
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

def permission_required(permission: str):
    """Decorator for routes that require specific permissions"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get current user from request context
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            
            if not request:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Internal server error"
                )
            
            try:
                user = await get_current_user_from_request(request)
                if not has_permission(user.get("role", get_default_role()), permission):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission denied. Required permission: {permission}"
                    )
                return await func(*args, **kwargs)
            except JWTError:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication credentials"
                )
        return wrapper
    return decorator

# User models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str
    
    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 20:
            raise ValueError('Username must be between 3 and 20 characters')
        if not re.match("^[a-zA-Z0-9_]+$", v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class UserLogin(BaseModel):
    username_or_email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    created_at: str

# Password reset models
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    confirm_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v
    
    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class RegistrationInitiateRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    confirm_password: str

    @validator('username')
    def validate_username(cls, v):
        if len(v) < 3 or len(v) > 20:
            raise ValueError('Username must be between 3 and 20 characters')
        if not re.match("^[a-zA-Z0-9_]+$", v):
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v

    @validator('password')
    def validate_password_reg(cls, v):
        if len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

    @validator('confirm_password')
    def passwords_match_reg(cls, v, values, **kwargs):
        if 'password' in values and v != values['password']:
            raise ValueError('Passwords do not match')
        return v

class RegistrationVerifyRequest(BaseModel):
    email: EmailStr
    otp_code: str

class VerifyOtpRequest(BaseModel):
    email: EmailStr
    otp_code: str

class CompletePasswordResetRequest(BaseModel):
    email: EmailStr
    new_password: str
    confirm_password: str

    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        return v

    @validator('confirm_password')
    def passwords_match(cls, v, values, **kwargs):
        if 'new_password' in values and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

class ResetPasswordWithOtpRequest(BaseModel):
    email: EmailStr
    otp_code: str
    new_password: Optional[str] = None
    confirm_password: Optional[str] = None

    @validator('new_password')
    def validate_password_reset_otp(cls, v):
        if v is not None and len(v) < 6:
            raise ValueError('Password must be at least 6 characters long')
        return v

    @validator('confirm_password')
    def passwords_match_reset_otp(cls, v, values, **kwargs):
        if 'new_password' in values and values['new_password'] is not None and v != values['new_password']:
            raise ValueError('Passwords do not match')
        return v

# Add role-related models and functions after existing models

class UserRole:
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @classmethod
    def get_all_roles(cls):
        return [cls.ADMIN, cls.ANALYST, cls.VIEWER]

    @classmethod
    def get_role_permissions(cls, role):
        """Get permissions for a specific role"""
        permissions = {
            cls.ADMIN: [
                "user_management",
                "system_settings",
                "view_reports",
                "manual_testing",
                "real_time_detection",
                "export_data",
                "delete_reports",
                "pcap_analysis",
                "alert_management",
                "view_alerts",
                "network_security"
            ],
            cls.ANALYST: [
                "view_reports",
                "manual_testing",
                "real_time_detection",
                "export_data",
                "pcap_analysis",
                "view_alerts",
                "network_security"
            ],
            cls.VIEWER: [
                "view_reports",
                "view_alerts"
            ]
        }
        return permissions.get(role, [])

    @classmethod
    def get_role_display_name(cls, role):
        """Get display name for role"""
        display_names = {
            cls.ADMIN: "System Administrator",
            cls.ANALYST: "Security Analyst",
            cls.VIEWER: "Report Viewer"
        }
        return display_names.get(role, "Unknown Role")

def get_default_role():
    """Get default role for new users"""
    return UserRole.VIEWER

def has_permission(user_role, permission):
    """Check if user role has specific permission"""
    role_permissions = UserRole.get_role_permissions(user_role)
    return permission in role_permissions

# Update ProfileUpdateRequest to include role (admin only)
class ProfileUpdateRequest(BaseModel):
    username: str
    email: Optional[str] = None

class AdminProfileUpdateRequest(BaseModel):
    username: str
    email: Optional[str] = None
    role: Optional[str] = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

# Utility functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def is_strong_password(password: str) -> bool:
    """Strong password policy: at least 8 chars, upper, lower, digit, special."""
    if not isinstance(password, str):
        return False
    if len(password) < 8:
        return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[]{};:'\",.<>/?|`~" for c in password)
    return has_upper and has_lower and has_digit and has_special

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = get_beijing_time() + expires_delta
    else:
        expire = get_beijing_time() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(username: str):
    return users_collection.find_one({"username": username})

def get_user_by_email(email: str):
    return users_collection.find_one({"email": email})

def authenticate_user(username: str, password: str):
    user = get_user_by_username(username)
    if not user:
        return False
    
    # Support both old and new password field names for backward compatibility
    hashed_password = user.get("hashed_password") or user.get("password")
    if not hashed_password:
        return False
    
    if not verify_password(password, hashed_password):
        return False
    return user

# Email utility functions
def send_reset_email(email: str, reset_token: str, username: str):
    """Send password reset email"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
        msg['Reply-To'] = FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = "PreTect-NIDS Password Reset Request"
        
        # Create reset link
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        
        # Email body
        body = f"""
        Hello {username},

        We received your password reset request. If you didn't initiate this, please ignore this email.

        To reset your password, please click the following link:
        {reset_link}

        This link will expire in 1 hour.

        If you didn't request a password reset, please ignore this email.

        Best regards,
        PreTect-NIDS Team
        """
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(FROM_EMAIL, email, text)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def create_reset_token(email: str) -> str:
    """Create a password reset token"""
    # Generate a secure random token
    token = secrets.token_urlsafe(32)
    
    # Store token in database with expiration
    expires_at = get_beijing_time() + timedelta(hours=1)
    
    reset_doc = {
        "email": email,
        "token": token,
        "expires_at": expires_at,
        "used": False,
        "created_at": get_beijing_time()
    }
    
    # Remove old tokens for this email
    password_reset_collection.delete_many({"email": email})
    
    # Insert new token
    password_reset_collection.insert_one(reset_doc)
    
    return token

def verify_reset_token(token: str) -> Optional[str]:
    """Verify reset token and return email if valid"""
    reset_doc = password_reset_collection.find_one({
        "token": token,
        "used": False,
        "expires_at": {"$gt": get_beijing_time()}
    })
    
    if reset_doc:
        return reset_doc["email"]
    return None

def mark_token_used(token: str):
    """Mark reset token as used"""
    password_reset_collection.update_one(
        {"token": token},
        {"$set": {"used": True}}
    )

# OTP utilities
def generate_otp_code() -> str:
    """Generate a 6-digit OTP code"""
    return f"{secrets.randbelow(10**6):06d}"

def send_verification_email(email: str, otp_code: str, username: str) -> bool:
    """Send registration verification OTP email"""
    try:
        # Dev-mode fallback: just print code and return success
        if EMAIL_DEV_MODE:
            print(f"[DEV] Registration OTP for {email}: {otp_code}")
            return True
        msg = MIMEMultipart()
        msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
        msg['Reply-To'] = FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = "PreTech-NIDS Email Verification Code"

        body = f"""
Hello {username},

Your verification code is: {otp_code}

Please enter this code in the website to complete your registration.
This code will expire in 10 minutes.

If you did not request this, please ignore this email.

Best regards,
PreTech-NIDS Team
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        # Ensure FROM matches SMTP username for strict providers
        if FROM_EMAIL and SMTP_USERNAME and FROM_EMAIL.lower() != SMTP_USERNAME.lower():
            print(f"[EmailConfig] Warning: FROM_EMAIL ({FROM_EMAIL}) != SMTP_USERNAME ({SMTP_USERNAME}). Many providers require them to match.")
        _smtp_send_message(msg, email)
        return True
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        if EMAIL_DEV_MODE:
            print(f"[DEV] Fallback success for registration OTP {otp_code} to {email}")
            return True
        # Raise to caller so it can return a clear 500 with detail
        raise

def send_reset_otp_email(email: str, otp_code: str, username: str) -> bool:
    """Send password reset OTP email"""
    try:
        # Dev-mode fallback: just print code and return success
        if EMAIL_DEV_MODE:
            print(f"[DEV] Password reset OTP for {email}: {otp_code}")
            return True
        msg = MIMEMultipart()
        msg['From'] = formataddr((FROM_NAME, FROM_EMAIL))
        msg['Reply-To'] = FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = "PreTech-NIDS Password Reset Code"

        body = f"""
Hello {username},

Your password reset code is: {otp_code}

Please enter this code in the website to reset your password.
This code will expire in 10 minutes.

If you did not request this, please ignore this email.

Best regards,
PreTech-NIDS Team
"""
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        if FROM_EMAIL and SMTP_USERNAME and FROM_EMAIL.lower() != SMTP_USERNAME.lower():
            print(f"[EmailConfig] Warning: FROM_EMAIL ({FROM_EMAIL}) != SMTP_USERNAME ({SMTP_USERNAME}). Many providers require them to match.")
        _smtp_send_message(msg, email)
        return True
    except Exception as e:
        print(f"Failed to send reset OTP email: {e}")
        if EMAIL_DEV_MODE:
            print(f"[DEV] Fallback success for reset OTP {otp_code} to {email}")
            return True
        raise

# Email utility functions
def send_reset_email(email: str, reset_token: str, username: str):
    """Send password reset email"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = email
        msg['Subject'] = "PreTect-NIDS Password Reset Request"
        
        # Create reset link
        reset_link = f"http://localhost:3000/reset-password?token={reset_token}"
        
        # Email body
        body = f"""
        Hello {username},

        We received your password reset request. If you didn't initiate this, please ignore this email.

        To reset your password, please click the following link:
        {reset_link}

        This link will expire in 1 hour.

        If you didn't request a password reset, please ignore this email.

        Best regards,
        PreTect-NIDS Team
        """
        
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        
        # Send email
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(FROM_EMAIL, email, text)
        server.quit()
        
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def create_reset_token(email: str) -> str:
    """Create a password reset token"""
    # Generate a secure random token
    token = secrets.token_urlsafe(32)
    
    # Store token in database with expiration
    expires_at = get_beijing_time() + timedelta(hours=1)
    
    reset_doc = {
        "email": email,
        "token": token,
        "expires_at": expires_at,
        "used": False,
        "created_at": get_beijing_time()
    }
    
    # Remove old tokens for this email
    password_reset_collection.delete_many({"email": email})
    
    # Insert new token
    password_reset_collection.insert_one(reset_doc)
    
    return token

def verify_reset_token(token: str) -> Optional[str]:
    """Verify reset token and return email if valid"""
    reset_doc = password_reset_collection.find_one({
        "token": token,
        "used": False,
        "expires_at": {"$gt": get_beijing_time()}
    })
    
    if reset_doc:
        return reset_doc["email"]
    return None

def mark_token_used(token: str):
    """Mark reset token as used"""
    password_reset_collection.update_one(
        {"token": token},
        {"$set": {"used": True}}
    )

# Avatar upload utility functions
async def save_avatar(file: UploadFile, username: str) -> str:
    """Save uploaded avatar and return filename"""
    try:
        # Validate file type
        if file.content_type not in ALLOWED_IMAGE_TYPES:
            raise ValueError("Invalid file type. Only JPEG, PNG, GIF, and WebP are allowed.")
        
        # Validate file size
        if file.size > MAX_AVATAR_SIZE:
            raise ValueError("File too large. Maximum size is 5MB.")
        
        # Generate unique filename
        file_extension = file.filename.split(".")[-1].lower()
        filename = f"{username}_{secrets.token_urlsafe(8)}.{file_extension}"
        file_path = AVATAR_UPLOAD_DIR / filename
        
        # Save file (ensure stream at beginning to avoid empty writes)
        with open(file_path, "wb") as buffer:
            try:
                file.file.seek(0)
            except Exception:
                pass
            shutil.copyfileobj(file.file, buffer)
        
        return filename
    except Exception as e:
        raise ValueError(f"Failed to save avatar: {str(e)}")

def get_avatar_url(filename: str) -> str:
    """Get avatar URL"""
    if not filename:
        return None
    # Return full URL for frontend access (localhost for development)
    return f"http://localhost:8000/static/avatars/{filename}"

def delete_old_avatar(username: str):
    """Delete old avatar file if exists"""
    try:
        user = users_collection.find_one({"username": username})
        if user and user.get("avatar"):
            old_avatar_path = AVATAR_UPLOAD_DIR / user["avatar"]
            if old_avatar_path.exists():
                old_avatar_path.unlink()
    except Exception as e:
        print(f"Failed to delete old avatar: {e}")

# Authentication routes
@router.post("/register", response_model=UserResponse)
def register_user(user: UserRegister):
    try:
        # Disallow direct registration unless explicitly enabled
        if os.getenv("ALLOW_DIRECT_REGISTRATION", "false").lower() not in ("1", "true", "yes"): 
            raise HTTPException(status_code=403, detail="Direct registration disabled. Use email verification flow.")

        # Check if username already exists
        if get_user_by_username(user.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already registered"
            )
        
        # Check if email already exists
        if get_user_by_email(user.email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        # Strong password policy check
        if not is_strong_password(user.password):
            raise HTTPException(status_code=400, detail="Password too weak. Use at least 8 chars with upper, lower, number and special character.")

        # Create new user
        hashed_password = get_password_hash(user.password)
        user_doc = {
            "username": user.username,
            "email": user.email,
            "hashed_password": hashed_password,
            "role": get_default_role(),  # Set default role
            "created_at": get_beijing_time_iso(),
            "updated_at": get_beijing_time_iso(),
            "is_active": True
        }
        
        result = users_collection.insert_one(user_doc)
        user_doc["id"] = str(result.inserted_id)
        
        return UserResponse(
            id=user_doc["id"],
            username=user_doc["username"],
            email=user_doc["email"],
            created_at=user_doc["created_at"]
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Registration failed: {str(e)}"
        )

@router.post("/register/initiate")
def initiate_registration(payload: RegistrationInitiateRequest):
    try:
        # Reject if already registered
        if get_user_by_username(payload.username):
            raise HTTPException(status_code=400, detail="Username already registered")
        if get_user_by_email(payload.email):
            raise HTTPException(status_code=400, detail="Email already registered")

        # Strong password policy check
        if not is_strong_password(payload.password):
            raise HTTPException(status_code=400, detail="Password too weak. Use at least 8 chars with upper, lower, number and special character.")

        # Generate OTP and store temp record
        otp_code = generate_otp_code()
        hashed_password = get_password_hash(payload.password)

        # Upsert verification record for this email
        registration_verifications_collection.delete_many({"email": payload.email})
        registration_verifications_collection.insert_one({
            "email": payload.email,
            "username": payload.username,
            "hashed_password": hashed_password,
            "otp_code": otp_code,
            "attempts": 0,
            "expires_at": get_beijing_time() + timedelta(minutes=10),
            "created_at": get_beijing_time()
        })

        # Send email
        if not send_verification_email(payload.email, otp_code, payload.username):
            raise HTTPException(status_code=500, detail="Failed to send verification email")

        return {"message": "Verification code sent to email"}
    except HTTPException:
        raise
    except Exception as e:
        # Surface detailed reason for 5xx (e.g., SMTP 535) to the client
        raise HTTPException(status_code=500, detail=f"Failed to send verification email: {str(e)}")

@router.post("/register/resend")
def resend_registration_code(payload: dict):
    """Resend verification code for an existing pending registration"""
    try:
        email = payload.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="Email is required")

        rec = registration_verifications_collection.find_one({
            "email": email,
            "expires_at": {"$gt": get_beijing_time()}
        })
        if not rec:
            # For security: do not reveal whether pending exists
            return {"message": "If the email is pending verification, a new code has been sent"}

        otp_code = generate_otp_code()
        registration_verifications_collection.update_one(
            {"_id": rec["_id"]},
            {"$set": {"otp_code": otp_code, "expires_at": get_beijing_time() + timedelta(minutes=10)}}
        )

        if not send_verification_email(email, otp_code, rec.get("username", "User")):
            raise HTTPException(status_code=500, detail="Failed to send verification email")

        return {"message": "Verification code resent"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Resend failed: {str(e)}")

@router.post("/register/verify", response_model=UserResponse)
def verify_registration(payload: RegistrationVerifyRequest):
    try:
        rec = registration_verifications_collection.find_one({
            "email": payload.email,
            "expires_at": {"$gt": get_beijing_time()}
        })
        if not rec:
            raise HTTPException(status_code=400, detail="Verification expired or not found")
        if str(rec.get("otp_code")) != str(payload.otp_code):
            # increment attempts
            registration_verifications_collection.update_one({"_id": rec["_id"]}, {"$inc": {"attempts": 1}})
            raise HTTPException(status_code=400, detail="Invalid verification code")

        # Create user
        if get_user_by_username(rec["username"]) or get_user_by_email(rec["email"]):
            # In case someone registered between initiate and verify
            registration_verifications_collection.delete_many({"email": payload.email})
            raise HTTPException(status_code=400, detail="User already exists")

        user_doc = {
            "username": rec["username"],
            "email": rec["email"],
            "hashed_password": rec["hashed_password"],
            "role": get_default_role(),
            "created_at": get_beijing_time_iso(),
            "updated_at": get_beijing_time_iso(),
            "is_active": True
        }
        result = users_collection.insert_one(user_doc)
        user_doc["id"] = str(result.inserted_id)

        # Clean up verification
        registration_verifications_collection.delete_many({"email": payload.email})

        return UserResponse(
            id=user_doc["id"],
            username=user_doc["username"],
            email=user_doc["email"],
            created_at=user_doc["created_at"]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@router.post("/login", response_model=Token)
def login_user(user: UserLogin, response: Response):
    try:
        # Find user by username or email
        existing_user = get_user_by_username(user.username_or_email)
        if not existing_user:
            # Try to find by email if username not found
            existing_user = get_user_by_email(user.username_or_email)
            if not existing_user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )

        # Check if account is active
        if existing_user.get("is_active") is False:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account disabled"
            )

        # Verify password (support old/new fields)
        hashed_password = existing_user.get("hashed_password") or existing_user.get("password")
        if not hashed_password or not verify_password(user.password, hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": existing_user["username"]},
            expires_delta=access_token_expires
        )

        # Set HTTP-only cookie for token
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            secure=False,  # In production use HTTPS and set True with SameSite=None
            samesite="lax",
            path="/"  # Ensure cookie is available for all paths
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            user={
                "id": str(existing_user["_id"]),
                "username": existing_user["username"],
                "email": existing_user.get("email", ""),
                "role": existing_user.get("role", get_default_role()),
                "role_display": UserRole.get_role_display_name(existing_user.get("role", get_default_role())),
                "permissions": UserRole.get_role_permissions(existing_user.get("role", get_default_role())),
                "avatar": existing_user.get("avatar"),
                "avatar_url": get_avatar_url(existing_user.get("avatar"))
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@router.post("/logout")
def logout_user(response: Response):
    try:
        # Clear the authentication cookie
        response.delete_cookie(key="access_token")
        return {"message": "Successfully logged out"}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Logout failed: {str(e)}"
        )

# Password reset routes (OTP flow)


@router.post("/password-reset/resend-otp")
async def resend_password_reset_otp():
    """Resend OTP code for password reset"""
    try:
        # This endpoint would need to know which user to resend to
        # For now, we'll require the user to go through the forgot password flow again
        raise HTTPException(status_code=400, detail="Please use the forgot password form to request a new code")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Resend password reset OTP error: {e}")
        raise HTTPException(status_code=500, detail="Failed to resend reset code")

@router.post("/password-reset/initiate-otp")
async def initiate_password_reset_otp(request: ForgotPasswordRequest):
    """Send OTP code for password reset. If email not found, return explicit error."""
    try:
        user = get_user_by_email(request.email)
        if not user:
            # Explicitly inform the client that the email is not registered
            raise HTTPException(status_code=404, detail="Email address is not registered")

        # Generate and store OTP
        otp_code = generate_otp_code()
        password_reset_collection.delete_many({"email": request.email})
        password_reset_collection.insert_one({
            "email": request.email,
            "otp_code": otp_code,
            "used": False,
            "attempts": 0,
            "expires_at": get_beijing_time() + timedelta(minutes=10),
            "created_at": get_beijing_time()
        })

        if not send_reset_otp_email(request.email, otp_code, user["username"]):
            raise HTTPException(status_code=500, detail="Failed to send reset code")

        return {"message": "Password reset code sent to email"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Forgot password OTP error: {e}")
        raise HTTPException(status_code=500, detail="Failed to process password reset request")

@router.post("/password-reset/verify-otp")
async def verify_otp(request: VerifyOtpRequest):
    """Verify OTP code for password reset"""
    try:
        # Find any valid password reset record with this OTP
        rec = password_reset_collection.find_one({
            "otp_code": request.otp_code,
            "used": False,
            "expires_at": {"$gt": get_beijing_time()}
        })
        
        if not rec:
            raise HTTPException(status_code=400, detail="Invalid or expired verification code")

        return {"message": "OTP verified successfully", "email": rec["email"]}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Verify OTP error: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify OTP")

@router.post("/password-reset/complete")
async def complete_password_reset(request: CompletePasswordResetRequest):
    """Complete password reset after OTP verification"""
    try:
        # Find the password reset record for this email
        rec = password_reset_collection.find_one({
            "email": request.email,
            "used": False,
            "expires_at": {"$gt": get_beijing_time()}
        })
        
        if not rec:
            raise HTTPException(status_code=400, detail="No valid password reset session found")

        # Strong password policy
        if not is_strong_password(request.new_password):
            raise HTTPException(status_code=400, detail="Password too weak. Use at least 8 chars with upper, lower, number and special character.")

        user = get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Disallow reusing the same password
        current_hashed = user.get("hashed_password") or user.get("password")
        if current_hashed and pwd_context.verify(request.new_password, current_hashed):
            raise HTTPException(status_code=400, detail="New password must be different from the current password")

        hashed_password = get_password_hash(request.new_password)
        result = users_collection.update_one(
            {"email": request.email},
            {"$set": {"hashed_password": hashed_password, "updated_at": get_beijing_time_iso()}}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")

        password_reset_collection.update_one({"_id": rec["_id"]}, {"$set": {"used": True}})
        return {"message": "Password reset successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Complete password reset error: {e}")
        raise HTTPException(status_code=500, detail="Failed to reset password")

# Deprecated: link-based reset; kept commented for reference
# @router.post("/forgot-password")
# async def forgot_password(request: ForgotPasswordRequest):
#     pass

# Deprecated: token-based reset; kept commented for reference
# @router.post("/reset-password")
# async def reset_password(request: ResetPasswordRequest):
#     pass

def get_current_user(request: Request):
    """Get current user from JWT token in cookie"""
    try:
        # Get token from cookie
        token = request.cookies.get("access_token")
        if token:
            # Remove "Bearer " prefix if present
            if token.startswith("Bearer "):
                token = token[7:]
            
            # Decode JWT token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return None
        else:
            return None
        
        # Get user from database
        user = get_user_by_username(username)
        return user
    
    except JWTError:
        return None

@router.get("/check-auth")
async def check_authentication(request: Request):
    """Check if user is authenticated"""
    try:
        # Get JWT token from cookie
        token = request.cookies.get("access_token")
        print(f"Check auth - cookies: {request.cookies}")
        print(f"Check auth - token: {token}")
        if not token:
            return {"authenticated": False, "user": None}
        
        # Remove "Bearer " prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return {"authenticated": False, "user": None}
        
        # Get user from database
        user = users_collection.find_one({"username": username})
        if not user:
            return {"authenticated": False, "user": None}
        
        return {
            "authenticated": True,
            "user": {
                "id": str(user["_id"]),
                "username": user["username"],
                "email": user.get("email", ""),
                "role": user.get("role", get_default_role()),
                "role_display": UserRole.get_role_display_name(user.get("role", get_default_role())),
                "permissions": UserRole.get_role_permissions(user.get("role", get_default_role())),
                "avatar": user.get("avatar"),
                "avatar_url": get_avatar_url(user.get("avatar"))
            }
        }
    except JWTError:
        return {"authenticated": False, "user": None}
    except Exception as e:
        print(f"Check auth error: {e}")
        return {"authenticated": False, "user": None}

@router.get("/me")
async def get_current_user(request: Request):
    """Get current user information"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get user from database
        user = users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Return user data (excluding password)
        return {
            "id": str(user["_id"]),
            "username": user["username"],
            "email": user.get("email", ""),
            "role": user.get("role", get_default_role()),
            "role_display": UserRole.get_role_display_name(user.get("role", get_default_role())),
            "permissions": UserRole.get_role_permissions(user.get("role", get_default_role())),
            "created_at": user.get("created_at"),
            "updated_at": user.get("updated_at"),
            "avatar": user.get("avatar"),
            "avatar_url": get_avatar_url(user.get("avatar"))
        }
        
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Get current user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/profile")
async def update_profile(profile_data: ProfileUpdateRequest, request: Request):
    """Update user profile information"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        current_username = payload.get("sub")
        if not current_username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate input
        if not profile_data.username.strip():
            raise HTTPException(status_code=400, detail="Username is required")
        
        if len(profile_data.username.strip()) < 3:
            raise HTTPException(status_code=400, detail="Username must be at least 3 characters long")
        
        # Check if new username already exists (if different from current)
        if profile_data.username.strip() != current_username:
            existing_user = users_collection.find_one({"username": profile_data.username.strip()})
            if existing_user:
                raise HTTPException(status_code=409, detail="Username already exists")
        
        # Update user in database
        update_data = {
            "username": profile_data.username.strip(),
            "updated_at": get_beijing_time_iso()
        }
        
        if profile_data.email is not None:
            if profile_data.email.strip():
                # Validate email format
                from email_validator import validate_email, EmailNotValidError
                try:
                    validate_email(profile_data.email.strip())
                    update_data["email"] = profile_data.email.strip()
                except EmailNotValidError:
                    raise HTTPException(status_code=400, detail="Invalid email format")
            else:
                update_data["email"] = ""
        
        result = users_collection.update_one(
            {"username": current_username},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get updated user data
        updated_user = users_collection.find_one({"username": profile_data.username.strip()})
        
        # Create new JWT token if username changed
        if profile_data.username.strip() != current_username:
            access_token = create_access_token(data={"sub": profile_data.username.strip()})
            
            # Update cookie with new token
            response = JSONResponse(content={
                "id": str(updated_user["_id"]),
                "username": updated_user["username"],
                "email": updated_user.get("email", ""),
                "role": updated_user.get("role", get_default_role()),
                "role_display": UserRole.get_role_display_name(updated_user.get("role", get_default_role())),
                "permissions": UserRole.get_role_permissions(updated_user.get("role", get_default_role())),
                "created_at": updated_user.get("created_at"),
                "updated_at": updated_user.get("updated_at"),
                "message": "Profile updated successfully"
            })
            response.set_cookie(
                key="access_token",
                value=access_token,
                httponly=True,
                max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                secure=False,
                samesite="lax"
            )
            return response
        else:
            return {
                "id": str(updated_user["_id"]),
                "username": updated_user["username"],
                "email": updated_user.get("email", ""),
                "role": updated_user.get("role", get_default_role()),
                "role_display": UserRole.get_role_display_name(updated_user.get("role", get_default_role())),
                "permissions": UserRole.get_role_permissions(updated_user.get("role", get_default_role())),
                "created_at": updated_user.get("created_at"),
                "updated_at": updated_user.get("updated_at"),
                "message": "Profile updated successfully"
            }
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Update profile error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/password")
async def change_password(password_data: PasswordChangeRequest, request: Request):
    """Change user password"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate input: strong password policy
        if not is_strong_password(password_data.new_password):
            raise HTTPException(status_code=400, detail="New password too weak. Use at least 8 chars with upper, lower, number and special character.")
        
        # Get user from database
        user = users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Verify current password - support both old and new field names
        hashed_password = user.get("hashed_password") or user.get("password")
        if not hashed_password or not pwd_context.verify(password_data.current_password, hashed_password):
            raise HTTPException(status_code=401, detail="Incorrect current password")
        
        # Hash new password
        hashed_new_password = pwd_context.hash(password_data.new_password)
        
        # Update password in database
        result = users_collection.update_one(
            {"username": username},
            {"$set": {
                "hashed_password": hashed_new_password,
                "updated_at": get_beijing_time_iso()
            }}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Change password error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/avatar")
async def upload_avatar(file: UploadFile = File(...), request: Request = None):
    """Upload user avatar"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file selected")
        
        # Save avatar
        try:
            filename = await save_avatar(file, username)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        
        # Delete old avatar
        delete_old_avatar(username)
        
        # Update user in database
        result = users_collection.update_one(
            {"username": username},
            {"$set": {
                "avatar": filename,
                "updated_at": get_beijing_time_iso()
            }}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {
            "message": "Avatar uploaded successfully",
            "avatar": filename,
            "avatar_url": get_avatar_url(filename)
        }
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Avatar upload error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/avatar")
async def delete_avatar(request: Request):
    """Delete user avatar"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get user from database
        user = users_collection.find_one({"username": username})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Delete avatar file if exists
        if user.get("avatar"):
            delete_old_avatar(username)
        
        # Update user in database
        result = users_collection.update_one(
            {"username": username},
            {"$set": {
                "avatar": None,
                "updated_at": get_beijing_time_iso()
            }}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "Avatar deleted successfully"}
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Avatar delete error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 

# Admin-only user management endpoints

@router.get("/users")
async def get_all_users(request: Request):
    """Get all users (admin only)"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get current user and check admin role
        current_user = users_collection.find_one({"username": username})
        if not current_user or current_user.get("role") != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Get all users
        users = list(users_collection.find({}, {"hashed_password": 0}))  # Exclude passwords
        
        # Format user data
        user_list = []
        for user in users:
            user_list.append({
                "id": str(user["_id"]),
                "username": user["username"],
                "email": user.get("email", ""),
                "role": user.get("role", get_default_role()),
                "role_display": UserRole.get_role_display_name(user.get("role", get_default_role())),
                "created_at": user.get("created_at"),
                "updated_at": user.get("updated_at"),
                "is_active": user.get("is_active", True)
            })
        
        return {"users": user_list}
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Get users error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.put("/users/{user_id}/role")
async def update_user_role(user_id: str, role_data: dict, request: Request):
    """Update user role (admin only)"""
    try:
        # Get JWT token from cookie using the helper function
        token = extract_token_from_request(request)
        
        # Verify and decode token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Get current user and check admin role
        current_user = users_collection.find_one({"username": username})
        if not current_user or current_user.get("role") != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Admin access required")
        
        # Validate new role
        new_role = role_data.get("role")
        if new_role not in UserRole.get_all_roles():
            raise HTTPException(status_code=400, detail="Invalid role")
        
        # Update user role
        from bson import ObjectId
        result = users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {
                "role": new_role,
                "updated_at": get_beijing_time_iso()
            }}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": f"User role updated to {UserRole.get_role_display_name(new_role)}"}
        
    except HTTPException:
        raise
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Update user role error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/users/{user_id}")
async def delete_user(user_id: str, request: Request):
    """Delete a user (admin only). Prevent self-deletion for safety."""
    try:
        # Auth and admin check
        token = extract_token_from_request(request)
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        requester_username = payload.get("sub")
        if not requester_username:
            raise HTTPException(status_code=401, detail="Invalid token")

        requester = users_collection.find_one({"username": requester_username})
        if not requester or requester.get("role") != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Admin access required")

        # Resolve target user
        from bson import ObjectId
        target = users_collection.find_one({"_id": ObjectId(user_id)})
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        if target.get("username") == requester_username:
            raise HTTPException(status_code=400, detail="You cannot delete your own account")

        # Delete avatar file if exists
        if target.get("avatar"):
            try:
                old_avatar_path = AVATAR_UPLOAD_DIR / target["avatar"]
                if old_avatar_path.exists():
                    old_avatar_path.unlink()
            except Exception:
                pass

        users_collection.delete_one({"_id": ObjectId(user_id)})
        return {"message": "User deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Delete user error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/roles")
async def get_available_roles():
    """Get all available roles and their permissions"""
    roles_info = []
    for role in UserRole.get_all_roles():
        roles_info.append({
            "role": role,
            "display_name": UserRole.get_role_display_name(role),
            "permissions": UserRole.get_role_permissions(role)
        })
    
    return {"roles": roles_info} 