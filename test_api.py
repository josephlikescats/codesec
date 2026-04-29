import requests
import json

# Test the test generation endpoint
url = "http://localhost:8000/api/v1/tests/generate"
payload = {
    "findings": [
        {
            "id": "command_injection_9",
            "category": "injection",
            "severity": "critical",
            "title": "Command Injection Vulnerability",
            "description": "Potential command injection: os.system() with potential user input",
            "code_snippet": "os.system(cmd)",
            "line_number": 9,
            "cwe_id": "CWE-78"
        }
    ],
    "language": "python"
}

response = requests.post(url, json=payload)
print(f"Test Generation Status: {response.status_code}")
result = response.json()
print(f"Tests generated: {result['count']}")
print(f"First test name: {result['tests'][0]['name'] if result['tests'] else 'None'}")

# Test the remediation endpoint
url2 = "http://localhost:8000/api/v1/fix/suggest"
response2 = requests.post(url2, json=payload)
print(f"\nRemediation Status: {response2.status_code}")
result2 = response2.json()
print(f"Suggestions generated: {result2['count']}")
print(f"First suggestion title: {result2['suggestions'][0]['title'] if result2['suggestions'] else 'None'}")