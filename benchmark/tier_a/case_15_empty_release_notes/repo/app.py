from crypto_helper import hash_token

def secure_token(val: str) -> str:
    return hash_token(val)
