import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/shaikn6/credit-arena/commits/375f87a7246ee48a5132c84bcc849be63bc248fe/check-runs',
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
except Exception as e:
    print("Error:", e)

