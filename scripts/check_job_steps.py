import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/shaikn6/credit-arena/actions/jobs/124934833946',
    headers={'User-Agent': 'Python'}
)
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print("Status:", data.get("status"))
        print("Conclusion:", data.get("conclusion"))
        print("Steps:")
        for s in data.get("steps", []):
            print(f"  - Step: {s.get('name')} | Conclusion: {s.get('conclusion')}")
except Exception as e:
    print("Error:", e)

