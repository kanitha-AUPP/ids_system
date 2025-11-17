from flask import Flask, render_template, request, redirect, url_for, session
import csv
import datetime
import os
from collections import defaultdict

app = Flask(__name__)
app.secret_key = "secret123"   # Change for production

# ---------------------------
# CSV FILES
# ---------------------------
CREDENTIALS_FILE = "credentials.csv"
LOG_FILE = "logs.csv"
SUSPICIOUS_LOG_FILE = "suspicious_logs.csv"

# Track failed attempts in memory
failed_attempts = {}
ip_attempts = defaultdict(int)

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
# Log Activity
# ---------------------------

def log_activity(username, ip, status, port="Unknown", attempts=0):
    """Write login events to logs.csv"""
    
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = [timestamp, username, ip, status, port, attempts]
    
    # Main log file
    logfile_exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not logfile_exists:
            writer.writerow(["timestamp", "username", "ip", "status", "port", "attempts"])
        writer.writerow(log_entry)
    
    # Separate suspicious log file for failed/suspicious activities
    if status in ["FAILED", "SUSPICIOUS", "PORT_SCANNING", "BRUTE_FORCE"]:
        suspicious_exists = os.path.exists(SUSPICIOUS_LOG_FILE)
        with open(SUSPICIOUS_LOG_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not suspicious_exists:
                writer.writerow(["timestamp", "username", "ip", "status", "port", "attempts", "threat_level"])
            
            # Determine threat level
            if status == "PORT_SCANNING" or attempts >= 10:
                threat_level = "HIGH"
            elif status == "SUSPICIOUS" or attempts >= 5:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
                
            writer.writerow(log_entry + [threat_level])

# ---------------------------
# Threat Detection Functions
# ---------------------------

def detect_port_scanning(ip, port):
    """Detect potential port scanning activity"""
    # Simple heuristic: if same IP tries many different ports in short time
    ip_attempts[ip] += 1
    
    # If IP has tried more than 5 different ports, flag as port scanning
    if ip_attempts[ip] > 5:
        return True
    return False

def detect_brute_force(username, ip):
    """Detect brute force attack patterns"""
    # Multiple failed attempts from same IP for different users
    recent_failures = 0
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Check last 10 minutes
                log_time = datetime.datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
                time_diff = datetime.datetime.utcnow() - log_time
                if time_diff.total_seconds() < 600:  # 10 minutes
                    if row["ip"] == ip and row["status"] in ["FAILED", "SUSPICIOUS"]:
                        recent_failures += 1
    
    return recent_failures > 8

# ---------------------------
# Routes
# ---------------------------

@app.route("/")
def index():
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        ip = request.remote_addr or "Unknown"
        port = request.environ.get("REMOTE_PORT", "Unknown")

        users = load_credentials()

        # -------- THREAT DETECTION --------
        threat_detected = False
        
        # Port Scanning Detection
        if detect_port_scanning(ip, port):
            log_activity(username, ip, "PORT_SCANNING", port, ip_attempts[ip])
            threat_detected = True
        
        # Brute Force Detection
        if detect_brute_force(username, ip):
            log_activity(username, ip, "BRUTE_FORCE", port, ip_attempts[ip])
            threat_detected = True
        
        if threat_detected:
            return render_template("error.html", 
                                 message="Suspicious activity detected. Access blocked.")

        # -------- SUCCESS LOGIN --------
        if username in users and users[username] == password:
            session["user"] = username
            failed_attempts[username] = 0
            log_activity(username, ip, "SUCCESS", port)
            
            # Redirect admin to dashboard, others to home
            if username == "admin" and password == "kannyxoxo":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("home"))

        # -------- FAILED LOGIN --------
        failed_attempts[username] = failed_attempts.get(username, 0) + 1
        attempts = failed_attempts[username]

        status = "SUSPICIOUS" if attempts >= 3 else "FAILED"

        log_activity(username, ip, status, port, attempts)

        # Show locked page after 5 attempts
        if attempts >= 5:
            return render_template("locked.html")
        
        return render_template("error.html", 
                             message=f"Login failed. Attempts: {attempts}")

    return render_template("login.html")

@app.route("/home")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("home.html")

@app.route("/admin/dashboard")
def admin_dashboard():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))
    
    # Load basic stats for dashboard
    stats = {
        "total_logins": 0,
        "successful": 0,
        "failed": 0,
        "suspicious": 0,
        "unique_users": set(),
        "unique_ips": set()
    }
    
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                stats["total_logins"] += 1
                stats["unique_users"].add(row["username"])
                stats["unique_ips"].add(row["ip"])
                
                if row["status"] == "SUCCESS":
                    stats["successful"] += 1
                elif row["status"] == "FAILED":
                    stats["failed"] += 1
                elif row["status"] == "SUSPICIOUS":
                    stats["suspicious"] += 1
    
    stats["unique_users"] = len(stats["unique_users"])
    stats["unique_ips"] = len(stats["unique_ips"])
    
    return render_template("admin_dashboard.html", stats=stats)

@app.route("/admin/activities")
def admin_activities():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))
    
    activities = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            activities = list(reader)
    
    # Show latest first
    activities.reverse()
    return render_template("admin_activity.html", activities=activities[:100])

@app.route("/admin/alerts")
def admin_alerts():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))
    
    alerts = []
    if os.path.exists(SUSPICIOUS_LOG_FILE):
        with open(SUSPICIOUS_LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            alerts = list(reader)
    
    # Show latest first
    alerts.reverse()
    return render_template("admin_alert.html", alerts=alerts)

@app.route("/admin/stats")
def admin_stats():
    if "user" not in session or session["user"] != "admin":
        return redirect(url_for("login"))
    
    stats = {
        "total_logins": 0,
        "successful": 0,
        "failed": 0,
        "suspicious": 0,
        "high_threats": 0,
        "unique_users": set(),
        "unique_ips": set()
    }
    
    # Analyze main logs
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                stats["total_logins"] += 1
                stats["unique_users"].add(row["username"])
                stats["unique_ips"].add(row["ip"])
                
                if row["status"] == "SUCCESS":
                    stats["successful"] += 1
                elif row["status"] == "FAILED":
                    stats["failed"] += 1
                elif row["status"] == "SUSPICIOUS":
                    stats["suspicious"] += 1
    
    # Analyze threat levels
    if os.path.exists(SUSPICIOUS_LOG_FILE):
        with open(SUSPICIOUS_LOG_FILE, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("threat_level") == "HIGH":
                    stats["high_threats"] += 1
    
    stats["unique_users"] = len(stats["unique_users"])
    stats["unique_ips"] = len(stats["unique_ips"])
    
    return render_template("admin_stats.html", stats=stats)

@app.route("/logout", methods=["POST"])
def logout():
    username = session.get("user", "Unknown")
    ip = request.remote_addr or "Unknown"
    port = request.environ.get("REMOTE_PORT", "Unknown")
    
    log_activity(username, ip, "LOGOUT", port)
    session.pop("user", None)
    
    return redirect(url_for("login"))

# ---------------------------
# Start App
# ---------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)