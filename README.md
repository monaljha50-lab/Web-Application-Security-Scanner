
# SecureScan — Web Application Security Scanner

A student-friendly Flask MVP for **authorized, passive, non-destructive** web security assessment.

## Features
- Dashboard with scan statistics and score
- Authorized URL confirmation
- SSRF protection against private/reserved IP targets
- Passive checks for HTTPS, security headers, clickjacking, CORS indicators, cookies, and server disclosure
- SQLite scan history
- JSON and PDF reports
- Responsive cybersecurity dashboard

## Run on Windows

1. Install Python 3.10+.
2. Open Command Prompt in this folder.
3. Create a virtual environment:

```bash
python -m venv .venv
```

4. Activate it:

```bash
.venv\Scripts\activate
```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

6. Start the application:

```bash
python app.py
```

7. Open:

http://127.0.0.1:5000

## Important security scope

Use this only against systems you own or have explicit authorization to assess.

This MVP intentionally does **not** include exploit payloads, brute force, authentication bypass, destructive tests, command execution, or vulnerability exploitation. It performs limited passive HTTP checks.

## Project structure

```text
web_app_security_scanner/
├── app.py
├── requirements.txt
├── README.md
├── scanner.db              # created automatically
├── templates/
│   └── index.html
└── static/
    ├── app.js
    └── style.css
```

## Notes for a college project

For a production deployment, add:
- HTTPS for the scanner itself
- Proper user authentication and authorization
- CSRF protection
- Server-side rate limiting
- Background scan jobs/queue
- Stronger target allowlisting
- Centralized audit logging
- Secret management
- Database migrations
- Reverse proxy and hardened deployment
