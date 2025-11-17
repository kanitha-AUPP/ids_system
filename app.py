from flask import Flask, render_template, request, redirect, url_for, session
import csv
import datetime
import os

app = Flask(__name__)
app.secret_key = "secret123"   # Change for production

# ---------------------------
# CSV FILES
# ---------------------------
CREDENTIALS_FILE = "credentials.csv"
LOG_FILE = "logs.csv"

# Track failed attempts in memory
failed_attempts = {}

# ---------------------------
# Load Credentials
# ---------------------------

def load_credentials():
    """Load usernames and passwords from credentials.csv"""
    users = {}

    if not os.path.exists(CREDENTIALS_FILE):
        print("⚠️ credentials.csv not found!")
        return users

    with open(CREDENTIALS_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            # support admin:pass OR admin,pass
            if ":" in line:
                username, password = line.split(":", 1)
            elif "," in line:
                username, password = line.split(",", 1)
            else:
                continue

            users[username.strip()] = password.strip()

    return users

# ---------------------------
# Log Activity to logs.csv
# ---------------------------

def log_activity(username, ip, status, port="Unknown", attempts=0):
    """Write login events to logs.csv"""

    logfile_exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Write header if file didn't exist
        if not logfile_exists:
            writer.writerow(["timestamp", "username", "ip", "status", "port", "attempts"])

        writer.writerow([
            datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            username,
            ip,
            status,
            port,
            attempts
        ])

# ---------------------------
# Routes
# ---------------------------

@app.route("/")
def index():
    return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        ip = request.remote_addr or "Unknown" #function to grep ip
        port = request.environ.get("REMOTE_PORT", "Unknown")

        users = load_credentials()

        # -------- SUCCESS LOGIN --------
        if username in users and users[username] == password:
            session["user"] = username
            failed_attempts[username] = 0
            log_activity(username, ip, "SUCCESS", port)
            return render_template("home.html")

        # -------- FAILED LOGIN --------
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        attempts = failed_attempts[username]

        status = "SUSPICIOUS" if attempts >= 3 else "FAILED"

        log_activity(username, ip, status, port, attempts)

        return render_template("error.html", msg=f"Login failed. Attempts: {attempts}")

    return render_template("login.html")

@app.route("/home")
def home():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("home.html")

# @app.route("/logout")
# def logout():
#     session.pop("user", None)
#     return redirect(url_for("index"))

# ---------------------------
# Start App
# ---------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
