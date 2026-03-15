import requests

important_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

url = input("Enter a website URL: ")

try:
    response = requests.get(url, timeout=5)

    print(f"\nStatus code: {response.status_code}")
    print("\nChecking important security headers...\n")

    for header in important_headers:
        if header in response.headers:
            print(f"[OK] {header}: {response.headers[header]}")
        else:
            print(f"[MISSING] {header}")

except requests.exceptions.RequestException as e:
    print("Error:", e)
