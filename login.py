from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import datetime
import os

# ---------------------------
# Flask Initialization
# ---------------------------
app = Flask(__name__)
app.secret_key = 'secret123'  # CHANGE IN PRODUCTION

# ---------------------------
# Database Configuration (MySQL ONLY)
# ---------------------------
# Require DATABASE_URL — no SQLite fallback
if "DATABASE_URL" not in os.environ:
    raise RuntimeError("❌ ERROR: DATABASE_URL environment variable not set. MySQL connection required.")

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Track failed login attempts in RAM
failed_attempts = {}

# ---------------------------
# Database Models
# ---------------------------

class User(db.Model):
    __tablename__ = 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    username = db.Column(db.String(80), nullable=False)
    ip = db.Column(db.String(40))
    status = db.Column(db.String(20))        # SUCCESS / FAILED / SUSPICIOUS
    port = db.Column(db.String(10))
    attempts = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Log {self.username} - {self.status}>'

# ---------------------------
# Helper Functions
# ---------------------------

def load_credentials(username):
    """Get user by username."""
    return User.query.filter_by(username=username).first()

def log_activity(username, ip, status, port='Unknown', attempts=0):
    """Logs user activity into MySQL."""
    new_log = Log(
        username=username,
        ip=ip,
        status=status,
        port=port,
        attempts=attempts
    )
    db.session.add(new_log)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Database log error:", e)

# ---------------------------
# Routes
# ---------------------------

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        ip = request.remote_addr or 'Unknown'
        port = request.environ.get('REMOTE_PORT', 'Unknown')

        user = load_credentials(username)

        # ---- Authentication ----
        if user and user.password_hash == password:
            session['user'] = username
            failed_attempts[username] = 0

            log_activity(username, ip, "SUCCESS", port)
            return render_template('home.html')

        # ---- Failed Login ----
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        attempts = failed_attempts[username]

        status = "SUSPICIOUS" if attempts >= 3 else "FAILED"
        log_activity(username, ip, status, port, attempts)

        return render_template('error.html', msg=f"Login failed. Attempts: {attempts}")

    return render_template('login.html')

@app.route('/home')
def home():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('home.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

# ---------------------------
# App Bootstrap
# ---------------------------

if __name__ == '__main__':
    with app.app_context():
        # Create tables
        db.create_all()
        print("✔ MySQL tables ensured.")

        # Seed initial users if table is empty
        if not User.query.first():
            initial_users = [
                ('admin', 'kannyxoxo'),
                ('user1', 'kan2005167122'),
                ('user2', 'whateveryouwanttodo'),
                ('alice', 'alice2025'),
                ('bob', 'bob_secure'),
                ('charlie', 'charlie123'),
                ('diana', 'letmein'),
                ('eve', 'eve_pw'),
                ('frank', 'frank!234'),
                ('grace', 'grace_pw_10')
            ]
            for username, password in initial_users:
                db.session.add(User(username=username, password_hash=password))
            db.session.commit()
            print("✔ All initial users added to 'credentials' table.")

    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)