# Encryption, bcrypt, etc.
from bcrypt import gensalt, hashpw, checkpw

def hash_password(password: str) -> str:
    return hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
