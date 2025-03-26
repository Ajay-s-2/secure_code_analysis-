import os
import datetime
import subprocess
from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
REPORT_FOLDER = 'reports'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Security Scanner
def run_scan(file_path, language):
    print(f"📄 Scanning file: {file_path} ({language})")

    if language == "python":
        cmd = f"bandit -r {file_path}"
    elif language == "javascript":
        cmd = f"eslint {file_path} --format json"
    elif language == "php":
        cmd = f"phpcs --standard=PSR2 {file_path}"
    else:
        return "❌ Unsupported file type!"

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print("🔍 Scan Completed. Logs:")
        print(result.stdout)
        return result.stdout
    except Exception as e:
        print(f"⚠️ Error running scan: {e}")
        return str(e)

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files or 'language' not in request.form:
            flash("❌ No file selected!")
            return redirect(request.url)

        file = request.files['file']
        language = request.form['language']

        if file.filename == '':
            flash("❌ No file selected!")
            return redirect(request.url)

        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            print(f"✅ File uploaded: {file_path}")

            scan_result = run_scan(file_path, language)

            # Save report
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            report_filename = f"report_{timestamp}.html"
            report_filepath = os.path.join(REPORT_FOLDER, report_filename)

            with open(report_filepath, "w", encoding="utf-8") as f:
                f.write(render_template('report.html', scan_result=scan_result))

            return render_template('result.html', scan_result=scan_result, report_filename=report_filename)

    return render_template('index.html')

@app.route('/reports/<filename>')
def download_report(filename):
    return send_from_directory(REPORT_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
