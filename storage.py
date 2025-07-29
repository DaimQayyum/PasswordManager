import json
import base64
from typing import Dict, Any, Optional, List, Tuple
from crypto import derive_key, encrypt, decrypt
import hashlib

# File format: base64(salt) + ':' + base64(nonce) + ':' + base64(tag) + ':' + base64(ciphertext)
# The plaintext JSON contains the vault data, recovery_hash, and security_questions

def encode_b64(data: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(data).decode()

def decode_b64(data: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(data.encode())

def save_vault(filename: str, data: Dict[str, Any], password: str, recovery_hash: Optional[str] = None, security_questions: Optional[List[Tuple[str, str]]] = None) -> None:
    """Encrypt and save the vault data to file. Optionally include recovery_hash and security_questions."""
    vault = data.copy()
    if recovery_hash:
        vault['recovery_hash'] = recovery_hash
    if security_questions:
        vault['security_questions'] = security_questions
    key, salt = derive_key(password)
    plaintext = json.dumps(vault).encode()
    ciphertext, nonce, tag = encrypt(plaintext, key)
    with open(filename, 'w') as f:
        f.write(f"{encode_b64(salt)}:{encode_b64(nonce)}:{encode_b64(tag)}:{encode_b64(ciphertext)}")

def load_vault(filename: str, password: str) -> Dict[str, Any]:
    """Load and decrypt the vault file, returning a Python dict. Includes recovery_hash and security_questions if present."""
    with open(filename, 'r') as f:
        content = f.read()
    salt_b64, nonce_b64, tag_b64, ciphertext_b64 = content.split(':')
    salt = decode_b64(salt_b64)
    nonce = decode_b64(nonce_b64)
    tag = decode_b64(tag_b64)
    ciphertext = decode_b64(ciphertext_b64)
    key, _ = derive_key(password, salt)
    plaintext = decrypt(ciphertext, key, nonce, tag)
    vault = json.loads(plaintext.decode())
    return vault

def set_recovery_code(vault_data: Dict[str, Any], recovery_code: str) -> Dict[str, Any]:
    """Set the recovery_hash in the vault data."""
    vault = vault_data.copy()
    vault['recovery_hash'] = hash_recovery_code(recovery_code)
    return vault

def check_recovery_code(vault_data: Dict[str, Any], recovery_code: str) -> bool:
    """Check if the recovery code matches the stored hash."""
    stored_hash = vault_data.get('recovery_hash')
    if not stored_hash:
        return False
    return stored_hash == hash_recovery_code(recovery_code)

def hash_recovery_code(recovery_code: str) -> str:
    return hashlib.sha256(recovery_code.encode()).hexdigest()

def set_security_questions(vault_data: Dict[str, Any], questions_and_answers: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Set the security questions and hashed answers in the vault data."""
    vault = vault_data.copy()
    hashed_qa = []
    for question, answer in questions_and_answers:
        hashed_answer = hash_answer(answer)
        hashed_qa.append((question, hashed_answer))
    vault['security_questions'] = hashed_qa
    return vault

def check_security_questions(vault_data: Dict[str, Any], questions_and_answers: List[Tuple[str, str]]) -> bool:
    """Check if the security question answers match the stored hashes."""
    stored_qa = vault_data.get('security_questions', [])
    if len(stored_qa) != len(questions_and_answers):
        return False
    
    for i, (question, answer) in enumerate(questions_and_answers):
        if i >= len(stored_qa):
            return False
        stored_question, stored_hash = stored_qa[i]
        if question != stored_question or stored_hash != hash_answer(answer):
            return False
    return True

def hash_answer(answer: str) -> str:
    """Hash a security question answer."""
    return hashlib.sha256(answer.lower().strip().encode()).hexdigest()

def get_security_questions(vault_data: Dict[str, Any]) -> List[str]:
    """Get the list of security questions from the vault."""
    security_qa = vault_data.get('security_questions', [])
    return [question for question, _ in security_qa]
