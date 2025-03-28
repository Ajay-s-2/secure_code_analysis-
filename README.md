A Flask-based web application that scans Python code for security vulnerabilities using Bandit, with user authentication and scan history tracking.

## Features ✨

- **Code Vulnerability Detection**:
  - SQL Injection
  - Command Injection
  - Hardcoded Secrets
  - Insecure Deserialization
  - 50+ other vulnerability checks
- **User Management**:
  - Secure registration/login
  - Password hashing
- **Scan Management**:
  - File upload interface
  - Historical scan results
  - Detailed vulnerability reports
- **Interactive UI**:
  - Severity filtering
  - CWE documentation links
  - Code snippet viewing

##Set up virtual environment:
bash:
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

##Install dependencies:
bash:
pip install -r requirements.txt

##Initialize database:
bash:
flask shell
>>> db.create_all()
>>> exit()

###Usage 🚀
Start the application:
bash:
flask run
Access in browser:
http://localhost:5000
Default test credentials:
Username: admin
Password: admin123 (change immediately after first login)

File Structure 📂
Copy
secure-code-scanner/
├── app.py                # Main application
├── scanner.py            # Vulnerability scanner
├── requirements.txt      # Dependencies
│
├── instance/             # Database files
│   └── scanner.db        # SQLite database
│
├── uploads/              # Temporary uploads
└── templates/            # HTML templates
    ├── base.html         # Base template
    ├── dashboard.html    # User dashboard
    ├── result.html       # Scan results
    └── ...               # Other pages
