import base64
import hashlib
import hmac
import secrets

ITERATIONS = 310_000
SALT_LENGTH = 16


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_LENGTH)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return (
        f"{ITERATIONS}$"
        f"{base64.b64encode(salt).decode()}$"
        f"{base64.b64encode(digest).decode()}"
    )


def verify_password(password: str, stored_value: str) -> bool:
    iterations_text, salt_b64, digest_b64 = stored_value.split("$")
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        int(iterations_text),
    )
    return hmac.compare_digest(candidate, expected)
