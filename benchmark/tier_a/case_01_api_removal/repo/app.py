import data_transformer

def run_pipeline(payload: str) -> str:
    """Executes transformation using legacy API."""
    return data_transformer.transform_legacy(payload)

