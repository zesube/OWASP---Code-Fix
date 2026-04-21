from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Optional


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000)
    return f"{salt}${digest.hex()}"


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class UserRecord:
    email: str
    password_hash: str
    reset_token_hash: Optional[str] = None
    reset_token_expires_at: Optional[datetime] = None


USERS = {
    "alice@example.com": UserRecord(
        email="alice@example.com",
        password_hash=hash_password("OriginalPassword!123"),
    )
}


def issue_reset_token(email: str) -> Optional[str]:
    user = USERS.get(email)
    if user is None:
        return None

    token = secrets.token_urlsafe(32)
    user.reset_token_hash = hash_reset_token(token)
    user.reset_token_expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
    return token


def reset_password(token: str, new_password: str):
    if len(new_password) < 12:
        return {"error": "Password must be at least 12 characters."}, 400

    token_hash = hash_reset_token(token)
    now = datetime.now(timezone.utc)

    user = next(
        (
            record
            for record in USERS.values()
            if record.reset_token_hash == token_hash
            and record.reset_token_expires_at is not None
            and record.reset_token_expires_at >= now
        ),
        None,
    )

    if user is None:
        return {"error": "Invalid or expired reset token."}, 400

    user.password_hash = hash_password(new_password)
    user.reset_token_hash = None
    user.reset_token_expires_at = None

    return {"message": "Password updated successfully."}, 200
