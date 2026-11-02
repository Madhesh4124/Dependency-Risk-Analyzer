import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/espinoso/mentorshipMatchingApp/commits/32ae509557372bc3601a446a832b66547423360e/check-runs',
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

