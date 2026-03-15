import requests
from colorama import Fore, Style, init
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin

init(autoreset=True)

IMPORTANT_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy"
]

INTERESTING_ENDPOINTS = [
    "/robots.txt",
    "/admin",
    "/login",
    "/dashboard",
    "/debug",
    "/backup",
    "/secret",
    "/flag",
    "/api",
    "/server-status",
    "/.git",
    "/phpinfo.php"
]

INTERESTING_KEYWORDS = [
    "flag", "admin", "debug", "test", "token", "secret",
    "password", "backup", "dev", "internal", "ctf"
]


def print_info(msg):
    print(Fore.CYAN + "[INFO] " + Style.RESET_ALL + msg)


def print_ok(msg):
    print(Fore.GREEN + "[OK] " + Style.RESET_ALL + msg)


def print_warn(msg):
    print(Fore.YELLOW + "[WARN] " + Style.RESET_ALL + msg)


def print_hit(msg):
    print(Fore.RED + "[FOUND] " + Style.RESET_ALL + msg)


def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url


def fetch_url(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return response
    except requests.exceptions.RequestException as e:
        print_warn(f"Could not fetch {url}: {e}")
        return None


def check_headers(response):
    print_info("Checking response headers...")

    headers = response.headers

    if "Server" in headers:
        print_hit(f"Server header leaked: {headers['Server']}")
    else:
        print_ok("No Server header leaked.")

    if "X-Powered-By" in headers:
        print_hit(f"X-Powered-By leaked: {headers['X-Powered-By']}")

    for header in headers:
        lower_header = header.lower()
        if "debug" in lower_header or "backend" in lower_header or "internal" in lower_header:
            print_hit(f"Suspicious custom header: {header} = {headers[header]}")

    print_info("Checking important security headers...")
    for header in IMPORTANT_HEADERS:
        if header in headers:
            print_ok(f"{header}: {headers[header]}")
        else:
            print_warn(f"Missing {header}")


def check_cookies(response):
    print_info("Checking cookies...")

    cookies = response.cookies
    if not cookies:
        print_ok("No cookies set.")
        return

    for cookie in cookies:
        print_hit(f"Cookie found: {cookie.name} = {cookie.value}")

        if not cookie.secure:
            print_warn(f"Cookie '{cookie.name}' missing Secure flag")

        # requests cookie object does not always expose httponly directly,
        # so we check raw header too.
    raw_set_cookie = response.headers.get("Set-Cookie", "")
    if raw_set_cookie:
        if "HttpOnly" not in raw_set_cookie:
            print_warn("Set-Cookie header missing HttpOnly")
        if "Secure" not in raw_set_cookie:
            print_warn("Set-Cookie header missing Secure")

        # Look for interesting cookie names
        lower_cookie = raw_set_cookie.lower()
        for word in ["admin", "debug", "auth", "token", "session"]:
            if word in lower_cookie:
                print_hit(f"Interesting cookie-related keyword found: {word}")


def check_html_comments(response):
    print_info("Checking HTML comments...")

    soup = BeautifulSoup(response.text, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    if not comments:
        print_ok("No HTML comments found.")
        return

    for comment in comments:
        text = comment.strip()
        if text:
            print_hit(f"HTML comment: {text}")


def keyword_hunt(response):
    print_info("Looking for interesting keywords in page source...")

    source = response.text.lower()
    found_any = False

    for keyword in INTERESTING_KEYWORDS:
        if keyword in source:
            print_hit(f"Keyword found in source: {keyword}")
            found_any = True

    if not found_any:
        print_ok("No obvious keywords found in source.")


def check_redirects(base_url):
    print_info("Checking redirect behavior...")

    test_paths = ["/login", "/admin", "/redirect", "/home"]

    for path in test_paths:
        full_url = urljoin(base_url, path)
        try:
            r = requests.get(full_url, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302, 303, 307, 308]:
                location = r.headers.get("Location", "")
                print_hit(f"{path} redirects to: {location}")
        except requests.exceptions.RequestException:
            pass


def check_endpoints(base_url):
    print_info("Checking common interesting endpoints...")

    for endpoint in INTERESTING_ENDPOINTS:
        full_url = urljoin(base_url, endpoint)
        try:
            r = requests.get(full_url, timeout=5, allow_redirects=False)
            if r.status_code in [200, 401, 403]:
                print_hit(f"{endpoint} -> status {r.status_code}")
            elif r.status_code in [301, 302]:
                location = r.headers.get("Location", "")
                print_hit(f"{endpoint} -> redirect {r.status_code} to {location}")
        except requests.exceptions.RequestException:
            pass


def main():
    print(Fore.MAGENTA + "=== Mini CTF Web Recon Scanner ===" + Style.RESET_ALL)
    url = input("Enter target URL: ").strip()
    url = normalize_url(url)

    response = fetch_url(url)
    if not response:
        return

    print_info(f"Target: {url}")
    print_info(f"Final URL: {response.url}")
    print_info(f"Status Code: {response.status_code}")
    print()

    check_headers(response)
    print()

    check_cookies(response)
    print()

    check_html_comments(response)
    print()

    keyword_hunt(response)
    print()

    check_redirects(url)
    print()

    check_endpoints(url)
    print()

    print(Fore.MAGENTA + "=== Scan Complete ===" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
