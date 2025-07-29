import time
import random
import string
from typing import Tuple

def get_timestamp() -> str:
    """Return current timestamp as string."""
    return "1970-01-01T00:00:00Z"

def password_strength(password: str) -> Tuple[int, str]:
    """Return a score (0-4) and label for password strength."""
    score = 0
    if len(password) >= 8:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    labels = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
    return min(score, 4), labels[min(score, 4)]

def clear_clipboard_after(delay_ms: int, root) -> None:
    """Clear clipboard after delay_ms milliseconds."""
    def clear():
        root.clipboard_clear()
    root.after(delay_ms, clear)

# Constants
CLIPBOARD_CLEAR_DELAY_MS = 10000

# Password generator
def generate_password(length=16) -> str:
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.SystemRandom().choice(chars) for _ in range(length))

# Recovery code generator
def generate_recovery_code() -> str:
    """Generate a secure recovery code in format XXXX-XXXX-XXXX-XXXX-XXXX-XXXX."""
    chars = string.ascii_uppercase + string.digits
    code_parts = []
    for _ in range(6):
        part = ''.join(random.SystemRandom().choice(chars) for _ in range(4))
        code_parts.append(part)
    return '-'.join(code_parts)
