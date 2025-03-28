from flask import Flask, request, render_template, redirect, url_for, session, flash, json
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import json
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'dev-secret-key'

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# File upload config
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'py'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    scans = db.relationship('Scan', backref='user', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    results = db.Column(db.Text)

# Custom Jinja filters
@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {'error': 'Invalid scan data'}

@app.template_filter('format_datetime')
def format_datetime(value):
    return value.strftime('%Y-%m-%d %H:%M')

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=session['user_id']).order_by(Scan.timestamp.desc()).all()
    return render_template("dashboard.html", scans=scans)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    if 'file' not in request.files:
        flash('No file uploaded', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))
    
    if not allowed_file(file.filename):
        flash('Only Python (.py) files allowed', 'danger')
        return redirect(url_for('index'))
    
    try:
        filename = f"{uuid.uuid4().hex}.py"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        from scanner import scan_code
        scan_result = scan_code(filepath)
        os.remove(filepath)
        
        if not isinstance(scan_result, dict):
            scan_result = {'error': 'Invalid scan results format'}
        
        new_scan = Scan(
            filename=file.filename,
            user_id=session['user_id'],
            results=json.dumps(scan_result, indent=2)
        )
        db.session.add(new_scan)
        db.session.commit()
        
        return render_template("result.html", scan_result=scan_result)
    
    except Exception as e:
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
        app.logger.error(f"Scan error: {str(e)}")
        flash('An error occurred during scanning', 'danger')
        return redirect(url_for('index'))

@app.route('/scan/<int:scan_id>')
@login_required
def view_scan(scan_id):
    scan = Scan.query.filter_by(id=scan_id, user_id=session['user_id']).first_or_404()
    try:
        scan_result = json.loads(scan.results)
    except json.JSONDecodeError as e:
        flash('Failed to parse scan results', 'danger')
        app.logger.error(f"JSON decode error: {str(e)}")
        return redirect(url_for('dashboard'))
    
    return render_template("result.html", scan_result=scan_result)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
