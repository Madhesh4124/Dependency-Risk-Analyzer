import vault_client

def retrieve_token() -> str:
    """Retrieves API token from vault."""
    return vault_client.get_secret("api_token")

