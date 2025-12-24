AuthHarvester

A CLI utility for Bug Bounty Hunters to quickly port authenticated sessions from Browser/Burp to Python.

AuthHarvester solves the tedious workflow of manually copying cookies and Authorization headers when writing proof-of-concept (PoC) scripts for IDOR, Broken Access Control, or BOLA testing.

Instead of pasting massive cookie strings into your code, this tool parses raw requests or cURL commands and exports a clean, reusable session.json file.

⚡ Features
Request Parsing:
cURL: Paste directly from Chrome/Firefox DevTools ("Copy as cURL").

Raw HTTP: Paste directly from Burp Suite Repeater.

Manual: Step-by-step entry for custom headers.

Smart Cleaning: Automatically strips request-specific headers that break Python scripts (e.g., Content-Length, Host, Connection) while preserving Cookie, Authorization, and X-CSRF-Token.

JSON Output: Saves sessions in a standardized format for easy reuse.

Dependency Free: Written in pure Python 3. No pip install required.

🚀 Installation

Bash

git clone https://github.com/Amine-Ben-Zero/auth_harvester.git

cd AuthHarvester

chmod +x auth_harvester.py

🛠 Usage

Run the script interactively:

Bash

python3 auth_harvester.py
You will be prompted to choose an input method:

1.Raw HTTP: Copy the entire request from Burp Suite (headers only usually suffices).

2.cURL: Right-click a network request in your browser -> Copy -> Copy as cURL.

3.Manual: Type the headers yourself.

The tool will validate that authentication data exists and save it to a JSON file (e.g., user_a.json).

📖 Workflow: IDOR Testing
The primary use case is separating Attacker and Victim sessions for Access Control testing.

1.Log in as User A (Attacker). Copy request as cURL. Run tool -> Save as attacker.json.
2.Log in as User B (Victim). Copy request as cURL. Run tool -> Save as victim.json.
3.Use the helper function below in your exploit script to swap sessions instantly.

