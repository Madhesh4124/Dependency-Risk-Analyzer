from auth_guard import verify_token

def is_authorized(user_token: str) -> bool:
    """Checks whether token is authorized."""
    return verify_token(user_token)

