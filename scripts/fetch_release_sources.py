import urllib.request
import json

packages = [
    ("fastapi", "0.141.1", "0.146.0"),
    ("sqlalchemy", "2.0.51", "2.1.6"),
    ("numpy", "2.5.2", "2.5.3"),
    ("pandas", "3.0.6", "3.1.0"),
    ("numpy", "2.4.6", "2.5.4"),
    ("cryptography", "46.0.7", "50.0.0"),
]

for pkg, old_v, new_v in packages:
    url = f"https://pypi.org/pypi/{pkg}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "Python"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            project_urls = data.get("info", {}).get("project_urls", {})
            releases = data.get("releases", {})
            print(f"=== {pkg} {old_v} -> {new_v} ===")
            print("Project URLs:", {k: v for k, v in project_urls.items() if any(w in k.lower() for w in ['release', 'change', 'doc', 'home', 'source'])})
            print(f"Old version in PyPI: {old_v in releases}")
            print(f"New version in PyPI: {new_v in releases}")
    except Exception as e:
        print(f"Error for {pkg}: {e}")

