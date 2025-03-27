from flask import Flask, request, render_template, jsonify, redirect, url_for
import os
import uuid
from werkzeug.utils import secure_filename
from scanner import scan_code

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'py', 'php', 'js'}
MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    lang = request.form.get("language")
    
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type. Allowed: .py, .php, .js"}), 400
    
    if lang not in ["python", "php", "javascript"]:
        return jsonify({"error": "Invalid language selection"}), 400
    
    # Generate unique filename to prevent overwrites and path traversal
    ext = file.filename.rsplit('.', 1)[1].lower()
    unique_filename = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(unique_filename))
    
    try:
        file.save(file_path)
        scan_result = scan_code(file_path, lang)
        os.remove(file_path)
        
        if 'error' in scan_result:
            return render_template("error.html", error=scan_result['error']), 500
            
        return render_template("result.html", scan_result=scan_result)
    except Exception as e:
        if os.path.exists(file_path):
            os.remove(file_path)
        app.logger.error(f"Error during scanning: {str(e)}")
        return render_template("error.html", error="An error occurred during scanning"), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template("error.html", error="File size exceeds 2MB limit"), 413

if __name__ == '__main__':
    app.run(debug=True)
