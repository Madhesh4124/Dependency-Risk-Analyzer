"""Static fallback mappings between PyPI distribution names and importable module names."""

from typing import Dict, List

# Common packages where PyPI distribution name != top-level import module name
STATIC_PACKAGE_TO_MODULE_MAP: Dict[str, List[str]] = {
    "beautifulsoup4": ["bs4"],
    "pyyaml": ["yaml"],
    "pillow": ["PIL"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "pydantic-core": ["pydantic_core"],
    "protobuf": ["google.protobuf"],
    "google-cloud-storage": ["google.cloud.storage"],
    "google-cloud-firestore": ["google.cloud.firestore"],
    # Synthetic benchmark packages
    "synthetic-yaml": ["s_yaml"],
    "data-transformer": ["data_transformer"],
    "math-solver": ["math_solver"],
    "api-client": ["api_client"],
    "text-styler": ["text_styler"],
    "vault-client": ["vault_client"],
    "auth-guard": ["auth_guard"],
    "logger-engine": ["logger_engine"],
}

