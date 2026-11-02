import json
import urllib.request

req = urllib.request.Request(
    'https://api.github.com/repos/cfdude/datacommons-mcp/commits/05bc0fc18b797e1b73395bc0d5a9495a3317dbdc/check-runs',
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

