import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/yajur408-lang/EarthOS/commits/5cad27fa867c0133786949b1a418d599a83d009f/check-runs',
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

