#!/usr/bin/env python3
import sys
import json
import re
import shlex
import datetime
from http.cookies import SimpleCookie

# ==========================================
# CONFIGURATION & CONSTANTS
# ==========================================

# Headers that usually don't contain Auth data and clutter the output
IGNORED_HEADERS = {
    'host', 'content-length', 'content-type', 'connection', 
    'upgrade-insecure-requests', 'accept', 'accept-encoding', 
    'accept-language', 'user-agent', 'sec-ch-ua', 'sec-ch-ua-mobile', 
    'sec-ch-ua-platform', 'sec-fetch-site', 'sec-fetch-mode', 
    'sec-fetch-user', 'sec-fetch-dest', 'if-none-match', 'if-modified-since'
}

# ANSI Colors for CLI
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log(msg, level="info"):
    if level == "info":
        print(f"{Colors.OKBLUE}[*] {msg}{Colors.ENDC}")
    elif level == "success":
        print(f"{Colors.OKGREEN}[+] {msg}{Colors.ENDC}")
    elif level == "warn":
        print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")
    elif level == "error":
        print(f"{Colors.FAIL}[-] {msg}{Colors.ENDC}")

# ==========================================
# CORE LOGIC
# ==========================================

class SessionParser:
    def __init__(self):
        self.session_data = {
            "cookies": {},
            "headers": {},
            "meta": {
                "created_at": str(datetime.datetime.now()),
                "source": "unknown"
            }
        }

    def _parse_cookie_string(self, cookie_str):
        """Converts a 'Cookie: a=b; c=d' string into a dictionary."""
        cookie = SimpleCookie()
        cookie.load(cookie_str)
        return {k: v.value for k, v in cookie.items()}

    def _clean_headers(self, raw_headers):
        """Filters out noise and separates Cookies from Headers."""
        clean_headers = {}
        cookies = {}

        for k, v in raw_headers.items():
            k_lower = k.lower()
            
            # Extract cookies specifically
            if k_lower == 'cookie':
                cookies.update(self._parse_cookie_string(v))
                continue
            
            # Skip ignored headers
            if k_lower in IGNORED_HEADERS:
                continue
            
            # Keep Authorization, CSRF tokens, and custom headers
            clean_headers[k] = v

        return clean_headers, cookies

    def from_raw_http(self, raw_text):
        """Parses a raw HTTP request (Burp Repeater style)."""
        self.session_data["meta"]["source"] = "raw_http"
        lines = raw_text.strip().split('\n')
        raw_headers = {}
        
        # Skip the first line (METHOD URI HTTP/1.1)
        for line in lines[1:]:
            if line == '' or line == '\r': break # Stop at body
            if ':' in line:
                key, value = line.split(':', 1)
                raw_headers[key.strip()] = value.strip()
        
        h, c = self._clean_headers(raw_headers)
        self.session_data["headers"] = h
        self.session_data["cookies"] = c

    def from_curl(self, curl_command):
        """Parses a cURL command string."""
        self.session_data["meta"]["source"] = "curl"
        
        # Sanitize newlines (often present when copying from Chrome DevTools)
        curl_command = curl_command.replace('\\\n', ' ').replace('\n', ' ')
        
        try:
            tokens = shlex.split(curl_command)
        except ValueError:
            log("Failed to parse cURL syntax. Ensure quotes are closed.", "error")
            return

        raw_headers = {}
        
        for i, token in enumerate(tokens):
            if token == '-H' or token == '--header':
                if i + 1 < len(tokens):
                    header_str = tokens[i+1]
                    if ':' in header_str:
                        key, value = header_str.split(':', 1)
                        raw_headers[key.strip()] = value.strip()
        
        h, c = self._clean_headers(raw_headers)
        self.session_data["headers"] = h
        self.session_data["cookies"] = c

    def from_manual(self):
        """Interactive manual entry."""
        self.session_data["meta"]["source"] = "manual"
        print(f"\n{Colors.OKCYAN}--- Manual Entry ---{Colors.ENDC}")
        
        # Auth Header
        auth = input("Enter Authorization Header Value (Enter to skip): ").strip()
        if auth:
            if "Bearer" in auth or "Basic" in auth:
                self.session_data["headers"]["Authorization"] = auth
            else:
                # Ask key if not obvious
                key = input("  -> Key name (default: Authorization): ").strip() or "Authorization"
                self.session_data["headers"][key] = auth

        # Cookies
        cookie_str = input("Enter raw Cookie string (key=val; key2=val2): ").strip()
        if cookie_str:
            self.session_data["cookies"] = self._parse_cookie_string(cookie_str)
        
        # CSRF/Other
        while True:
            custom = input("Add custom header? (key:value) or Enter to finish: ").strip()
            if not custom: break
            if ':' in custom:
                k, v = custom.split(':', 1)
                self.session_data["headers"][k.strip()] = v.strip()

    def validate(self):
        """Checks if we actually captured authentication material."""
        has_cookies = len(self.session_data["cookies"]) > 0
        has_auth_header = any(k.lower() == 'authorization' for k in self.session_data["headers"])
        has_tokens = any('token' in k.lower() or 'csrf' in k.lower() for k in self.session_data["headers"])

        if not (has_cookies or has_auth_header or has_tokens):
            log("No obvious authentication markers (Cookies, Auth Header, CSRF) found.", "warn")
            return False
        return True

    def save(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.session_data, f, indent=2)
        log(f"Session saved to {Colors.BOLD}{filename}{Colors.ENDC}", "success")

# ==========================================
# UI / INTERACTION
# ==========================================

def get_multiline_input():
    print(f"{Colors.HEADER}(Paste your data below. Press Enter then Ctrl+D (Linux/Mac) or Ctrl+Z (Win) to finish){Colors.ENDC}")
    contents = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents.append(line)
    return "\n".join(contents)

def main():
    print(f"{Colors.BOLD}{Colors.OKGREEN}Authenticated Session Harvester{Colors.ENDC}")
    print("Prepare your authenticated request from Burp Suite or Browser DevTools.\n")

    parser = SessionParser()

    print("Select Input Mode:")
    print("1. Raw HTTP Request (Copy from Burp Repeater)")
    print("2. cURL Command (Copy as cURL from Chrome/Firefox)")
    print("3. Manual Entry")
    
    choice = input(f"\n{Colors.OKBLUE}Choice [1-3]: {Colors.ENDC}").strip()

    if choice == '1':
        raw_data = get_multiline_input()
        if not raw_data: return
        parser.from_raw_http(raw_data)
        
    elif choice == '2':
        raw_data = get_multiline_input()
        if not raw_data: return
        parser.from_curl(raw_data)
        
    elif choice == '3':
        parser.from_manual()
    else:
        log("Invalid selection.", "error")
        return

    # Validation
    print("\n--- Analysis ---")
    parser.validate()
    
    # Preview
    print(f"{Colors.OKCYAN}Captured Cookies:{Colors.ENDC} {len(parser.session_data['cookies'])}")
    print(f"{Colors.OKCYAN}Captured Headers:{Colors.ENDC} {json.dumps(parser.session_data['headers'], indent=2)}")

    # Confirmation
    confirm = input(f"\n{Colors.WARNING}Save this session? [Y/n]: {Colors.ENDC}").lower()
    if confirm in ('', 'y', 'yes'):
        filename = input(f"Filename (default: session.json): ").strip() or "session.json"
        if not filename.endswith(".json"):
            filename += ".json"
        parser.save(filename)
    else:
        log("Discarded.", "warn")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
