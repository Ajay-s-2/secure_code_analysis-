from flask import Flask, request, jsonify, send_from_directory
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, create_refresh_token
)
from flask_cors import CORS

app = Flask(__name__, static_folder='static')
CORS(app)
app.config["JWT_SECRET_KEY"] = "supersecretkey"
jwt = JWTManager(app)

# Mock database
users = {
    "admin": {"password": "adminpass", "role": "Admin"},
    "dev": {"password": "devpass", "role": "Developer"},
    "analyst": {"password": "analystpass", "role": "Security Analyst"}
}

reports = {
    1: {
        "id": 1,
        "title": "Initial Scan Report",
        "vulnerabilities": [
            {"name": "SQL Injection", "severity": "High", "recommendation": "Use parameterized queries"},
            {"name": "XSS", "severity": "Medium", "recommendation": "Sanitize user input"}
        ]
    }
}

@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    user = users.get(username)
    if user and user['password'] == password:
        additional_claims = {"role": user['role']}
        access_token = create_access_token(identity=username, additional_claims=additional_claims)
        return jsonify({
            "access_token": access_token,
            "role": user['role']
        })
    return jsonify({"msg": "Invalid credentials"}), 401

@app.route('/upload', methods=['POST'])
@jwt_required()
def upload_code():
    code = request.json.get('code')
    report_id = len(reports) + 1
    reports[report_id] = {
        "id": report_id,
        "title": f"Scan Report {report_id}",
        "vulnerabilities": [
            {"name": "Example Vulnerability", "severity": "High", "recommendation": "Fix this"}
        ]
    }
    return jsonify({"message": "Code analysis started", "report_id": report_id})

@app.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    return jsonify(list(reports.values()))

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    role = users[current_user]['role']
    return jsonify({"username": current_user, "role": role})

if __name__ == '__main__':
    app.run(debug=True)