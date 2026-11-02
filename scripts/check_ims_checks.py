import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/sinan-can-demir/ims/commits/8acbb1fb87b9477875e6249d9c29e23d48dd29ae/check-runs',
    headers={'User-Agent': 'Python'}
)
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        for cr in data.get('check_runs', []):
            name = cr.get('name')
            status = cr.get('status')
            conclusion = cr.get('conclusion')
            print(f"Check: {name} | Status: {status} | Conclusion: {conclusion}")
            print(f"Details URL: {cr.get('details_url')}")
            print("Summary:", cr.get('output', {}).get('summary'))
            print("Title:", cr.get('output', {}).get('title'))
except Exception as e:
    print("Error:", e)

