import requests
import json

# Test the scan endpoint
url = "http://localhost:8000/api/v1/scan"
payload = {
    "code": "import os\nimport subprocess\n\ndef get_user(user_id):\n    query = f'SELECT * FROM users WHERE id = {user_id}'\n    return db.execute(query)\n\ndef run_command(cmd):\n    os.system(cmd)\n\nAPI_KEY = \"sk-1234567890abcdef\"",
    "language": "python"
}

response = requests.post(url, json=payload)
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")