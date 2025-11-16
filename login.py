from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import datetime
import os
import csv

# --- Flask App Initialization ---
app = Flask(__name__)
app.secret_key = 'secret123'  # change in production

# --- Database Configuration ---
# Use SQLite database file named 'app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Files (Only used here for the one-time migration)
CREDENTIALS_FILE = 'credentials.csv'

# Track failed attempts (remains in memory for rate limiting)
failed_attempts = {}

# --- Database Models ---

class User(db.Model):
    """Model for storing user credentials. This table will now be named 'credentials'."""
    __tablename__ = 'credentials' # Explicitly set the table name to 'credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    # password_hash stores the plain password for simplicity, but should be a hash in production!
    password_hash = db.Column(db.String(120), nullable=False) 

    def __repr__(self):
        return f'<User {self.username}>'

class Log(db.Model):
    """Model for storing user activity and error logs."""
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    username = db.Column(db.String(80), nullable=False)
    ip = db.Column(db.String(40))
    status = db.Column(db.String(20)) # e.g., 'SUCCESS', 'FAILED', 'SUSPICIOUS'
    port = db.Column(db.String(10))
    attempts = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<Log {self.username} - {self.status}>'

# --- Database Operations Functions ---

def load_credentials(username):
    """Retrieve user object by username."""
    # This query now searches the 'credentials' table
    return User.query.filter_by(username=username).first()

def log_activity(username, ip, status, port='Unknown', attempts=0):
    """Create and commit a new log entry to the database."""
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
        print(f"Error logging activity: {e}")

# --- Flask Routes ---

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

        # Check credentials
        if user and user.password_hash == password:
            session['user'] = username
            failed_attempts[username] = 0
            log_activity(username, ip, 'SUCCESS', port)
            return render_template('home.html')
        else:
            # increment failed attempts
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            attempts = failed_attempts[username]
            status = 'SUSPICIOUS' if attempts >= 3 else 'FAILED'
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

# --- Application Startup (Includes Database Seeding and Migration) ---

if __name__ == '__main__':
    
    # Define the specific list of correct credentials you want to add
    NEW_USERS_TO_ADD = [
        ('admin', 'kannyxoxo'),
        ('user1', 'kan2005167122'),
        ('user2', 'whateveryouwanttodo'),
        ('alice', 'alice2025'),
        ('bob', 'bob_secure'),
        ('charlie', 'charlie123'),
        ('diana', 'letmein'),
        ('eve', 'eve_pw'),
        ('frank', 'frank!234'),
        ('grace', 'grace_pw_10'),
    ]

    with app.app_context():
        # 1. Create database file and all tables if they don't exist
        db.create_all()

        # 2. Check if the User table (now named 'credentials') is empty
        if not User.query.first():
            print("*** Running Initial User Seeding and CSV Migration ***")
            
            users_to_commit = []
            
            # A. Add users from your hardcoded list
            for username, password in NEW_USERS_TO_ADD:
                users_to_commit.append(User(username=username, password_hash=password))
            
            print(f"Adding {len(users_to_commit)} hardcoded users.")

            # B. Run CSV Migration (Existing logic to pull from credentials.csv, avoiding duplicates)
            imported_count = 0
            if os.path.exists(CREDENTIALS_FILE):
                try:
                    with open(CREDENTIALS_FILE, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith('#') or ':' not in line:
                                continue
                            
                            username, password = line.split(':', 1)
                            username = username.strip()
                            password = password.strip()
                            
                            # Only import if the user is NOT already in the hardcoded list
                            if not any(u.username == username for u in users_to_commit):
                                users_to_commit.append(User(username=username, password_hash=password))
                                imported_count += 1
                                
                    print(f"Imported {imported_count} users from {CREDENTIALS_FILE}.")
                        
                except Exception as e:
                    print(f"*** Migration Failed: Error during CSV import: {e} ***")
            else:
                print(f"No '{CREDENTIALS_FILE}' found for migration.")
                
            # C. Commit all new users to the database
            if users_to_commit:
                db.session.add_all(users_to_commit)
                try:
                    db.session.commit()
                    # Check the count from the actual table
                    print(f"*** Initial setup complete. Total users added to 'credentials' table: {len(User.query.all())} ***")
                except Exception as e:
                    db.session.rollback()
                    print(f"Failed to commit initial users: {e}")

        else:
            print("Credentials table already populated. Skipping initial setup.")


    port = int(os.environ.get("PORT", 8000))
    app.run(host='0.0.0.0', port=port, debug=True)