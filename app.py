from flask import Flask, render_template, request, redirect, url_for, session
import csv
import datetime
import os

app = Flask(__name__)
app.secret_key = 'secret123'  # change in production

# Files
CREDENTIALS_FILE = 'credentials.csv'
LOG_FILE = 'users.csv'
ERROR_LOG = 'error_logs.csv'

# Track failed attempts
failed_attempts = {}

def load_credentials():
    """Read credentials.txt and return a dict {username: password}."""
    creds = {}
    if not os.path.exists(CREDENTIALS_FILE):
        return creds
    with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                user, pwd = line.split(':', 1)
                creds[user.strip()] = pwd.strip()
    return creds

def log_activity(username, ip, status, port='Unknown', attempts=0):
    """Write logs into CSV file."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # standard log: [Time stamp] [username][IP address][Status][Port]
    # error log: [Time stamp] [username][IP address][Status][Port][amount of attempts]
    if status in ('FAILED', 'SUSPICIOUS'):
        row = [timestamp, username, ip, status, port, attempts]
        filename = ERROR_LOG
    else:
        row = [timestamp, username, ip, status, port]
        filename = LOG_FILE

    # Ensure header exists (optional)
    file_exists = os.path.exists(filename)
    with open(filename, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            # write header
            if filename == ERROR_LOG:
                writer.writerow(['timestamp', 'username', 'ip', 'status', 'port', 'attempts'])
            else:
                writer.writerow(['timestamp', 'username', 'ip', 'status', 'port'])
        writer.writerow(row)

@app.route('/')
def index():
    print("Rendering login page")
    return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        ip = request.remote_addr or 'Unknown'
        port = request.environ.get('REMOTE_PORT', 'Unknown')

        creds = load_credentials()  # read credentials on each attempt

        # If admin exists in creds and matches
        # if username == 'admin' and creds.get('admin') and creds.get('admin') == password:
        #     session['user'] = username
        #     log_activity(username, ip, 'ADMIN LOGIN', port)
        #     return redirect(url_for('admin_dashboard'))

        # Normal user login
        if username in creds and creds[username] == password:
            session['user'] = username
            failed_attempts[username] = 0  # reset failed count
            log_activity(username, ip, 'SUCCESS', port)
            return render_template('home.html')
        else:
            # increment failed attempts for the username (use username even if unknown)
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            attempts = failed_attempts[username]
            status = 'SUSPICIOUS' if attempts >= 3 else 'FAILED'
            log_activity(username, ip, status, port, attempts)
            return render_template('error.html', msg=f"Login failed. Attempts: {attempts}")
        
    return render_template('login.html')

@app.route('/home')
def home():
    return render_template('home.html')

# @app.route('/admin')
# def admin_dashboard():
#     if 'user' in session and session['user'] == 'admin':
#         user_logs = []
#         error_logs = []
#         try:
#             with open(LOG_FILE, newline='', encoding='utf-8') as f:
#                 reader = csv.reader(f)
#                 user_logs = list(reader)
#         except FileNotFoundError:
#             user_logs = []

#         try:
#             with open(ERROR_LOG, newline='', encoding='utf-8') as f:
#                 reader = csv.reader(f)
#                 error_logs = list(reader)
#         except FileNotFoundError:
#             error_logs = []

#         return render_template('admin.html', user_logs=user_logs, error_logs=error_logs)
#     return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # create empty log files if needed (optional)
    for fn in (LOG_FILE, ERROR_LOG):
        if not os.path.exists(fn):
            with open(fn, 'w', newline='', encoding='utf-8') as f:
                pass
    app.run(host='0.0.0.0', port=port, debug=True)
