from flask import Flask, g, request, redirect, url_for, session, render_template
import sqlite3, os, uuid
from functools import wraps
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash

# =====================================================
# APP CONFIG
# =====================================================
app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config["APP_NAME"] = "HostelEase"

DATABASE = os.path.join("database", "hostel.db")
ADMIN_SECRET_KEY = "HOSTEL_ADMIN_2026"

# =====================================================
# DATABASE
# =====================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()

# =====================================================
# DECORATORS
# =====================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def student_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "STUDENT":
            return "Access Denied"
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "ADMIN":
            return "Access Denied"
        return f(*args, **kwargs)
    return wrapper

# =====================================================
# HOME
# =====================================================
@app.route("/")
def home():
    return redirect(url_for("login"))

# =====================================================
# REGISTER
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        user_name = request.form.get("user_name")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")
        admin_key = request.form.get("admin_key")

        if not all([user_id, user_name, email, password, role]):
            return "All fields are required"

        if role == "ADMIN" and admin_key != ADMIN_SECRET_KEY:
            return "Unauthorized admin creation"

        hashed_pw = generate_password_hash(password)
        db = get_db()

        try:
            db.execute(
                """
                INSERT INTO users (user_id, user_name, email, password, role)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, user_name, email, hashed_pw, role)
            )
            db.commit()
        except sqlite3.IntegrityError:
            return "User ID or Email already exists"
        except Exception as e:
            return f"Registration failed: {e}"

        return redirect(url_for("login"))

    return render_template("register.html")

# =====================================================
# LOGIN / LOGOUT
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_id = request.form.get("user_id")
        password = request.form.get("password")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["logged_in"] = True
            session["user_id"] = user["user_id"]
            session["user_name"] = user["user_name"]
            session["role"] = user["role"]

            return redirect(
                "/admin/dashboard" if user["role"] == "ADMIN"
                else "/student/dashboard"
            )

        return "Invalid credentials"

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# =====================================================
# STUDENT DASHBOARD
# =====================================================
@app.route("/student/dashboard")
@login_required
@student_required
def student_dashboard():
    return render_template(
        "student_dashboard.html",
        name=session["user_name"]
    )

# =====================================================
# STUDENT OUTPASS
# =====================================================
@app.route("/student/outpass")
@login_required
@student_required
def view_outpass():
    db = get_db()
    requests = db.execute(
        "SELECT * FROM outpass_requests WHERE user_id=? ORDER BY applied_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("view_outpass.html", requests=requests)

@app.route("/student/outpass/apply", methods=["GET", "POST"])
@login_required
@student_required
def apply_outpass():
    if request.method == "POST":
        from_date = request.form["from_date"]
        to_date = request.form["to_date"]
        reason = request.form["reason"]

        from_dt = datetime.strptime(from_date, "%Y-%m-%d").date()
        to_dt = datetime.strptime(to_date, "%Y-%m-%d").date()

        if from_dt < date.today() or to_dt < from_dt:
            return "Invalid dates"

        outpass_id = "OP" + uuid.uuid4().hex[:4].upper()
        db = get_db()
        db.execute(
            """
            INSERT INTO outpass_requests
            (outpass_id, user_id, from_date, to_date, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (outpass_id, session["user_id"], from_date, to_date, reason)
        )
        db.commit()

        return redirect(url_for("view_outpass"))

    return render_template("apply_outpass.html")

@app.route("/student/outpass/cancel/<outpass_id>", methods=["POST"])
@login_required
@student_required
def cancel_outpass(outpass_id):
    db = get_db()
    db.execute(
        """
        DELETE FROM outpass_requests
        WHERE outpass_id=? AND user_id=? AND status='PENDING'
        """,
        (outpass_id, session["user_id"])
    )
    db.commit()
    return redirect(url_for("view_outpass"))

# =====================================================
# STUDENT COMPLAINTS
# =====================================================
@app.route("/student/complaint/new", methods=["GET", "POST"])
@login_required
@student_required
def new_complaint():
    if request.method == "POST":
        hostel = request.form["hostel"]
        room_no = request.form["room_no"]
        category = request.form["category"]
        description = request.form["description"]

        complaint_id = "C" + uuid.uuid4().hex[:5].upper()
        db = get_db()
        db.execute(
            """
            INSERT INTO complaints
            (complaint_id, user_id, hostel, room_no, category, description)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (complaint_id, session["user_id"],
             hostel, room_no, category, description)
        )
        db.commit()
        return redirect(url_for("view_complaints"))

    return render_template("new_complaint.html")

@app.route("/student/complaints")
@login_required
@student_required
def view_complaints():
    db = get_db()
    complaints = db.execute(
        "SELECT * FROM complaints WHERE user_id=? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("view_complaints.html", complaints=complaints)

# =====================================================
# NOTIFICATIONS
# =====================================================
def create_notification(user_id, message):
    db = get_db()
    nid = "N" + uuid.uuid4().hex[:6].upper()
    db.execute(
        "INSERT INTO notifications (notification_id, user_id, message) VALUES (?, ?, ?)",
        (nid, user_id, message)
    )
    db.commit()

@app.route("/student/notifications")
@login_required
@student_required
def student_notifications():
    db = get_db()
    notes = db.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC",
        (session["user_id"],)
    ).fetchall()
    return render_template("student_notifications.html", notifications=notes)

# =====================================================
# ADMIN DASHBOARD
# =====================================================
@app.route("/admin/dashboard")
@login_required
@admin_required
def admin_dashboard():
    db = get_db()
    pending_outpasses = db.execute(
        "SELECT COUNT(*) FROM outpass_requests WHERE status='PENDING'"
    ).fetchone()[0]
    open_complaints = db.execute(
        "SELECT COUNT(*) FROM complaints WHERE status!='CLOSED'"
    ).fetchone()[0]

    return render_template(
        "admin_dashboard.html",
        pending_outpasses=pending_outpasses,
        open_complaints=open_complaints
    )

# =====================================================
# ADMIN OUTPASS APPROVAL
# =====================================================
@app.route("/admin/outpasses")
@login_required
@admin_required
def admin_outpasses():
    db = get_db()
    requests = db.execute(
        """
        SELECT o.outpass_id, o.from_date, o.to_date, o.reason,
               u.user_id, u.user_name
        FROM outpass_requests o
        JOIN users u ON o.user_id = u.user_id
        WHERE o.status='PENDING'
        """
    ).fetchall()
    return render_template("admin_outpasses.html", requests=requests)

@app.route("/admin/outpass/<outpass_id>/<action>", methods=["POST"])
@login_required
@admin_required
def admin_outpass_action(outpass_id, action):
    status = "APPROVED" if action == "approve" else "REJECTED"
    db = get_db()

    db.execute(
        "UPDATE outpass_requests SET status=? WHERE outpass_id=?",
        (status, outpass_id)
    )

    user_id = db.execute(
        "SELECT user_id FROM outpass_requests WHERE outpass_id=?",
        (outpass_id,)
    ).fetchone()["user_id"]

    create_notification(user_id, f"Outpass {outpass_id} {status}")
    db.commit()

    return redirect(url_for("admin_outpasses"))

# =====================================================
# ADMIN COMPLAINTS
# =====================================================
@app.route("/admin/complaints")
@login_required
@admin_required
def admin_complaints():
    db = get_db()
    complaints = db.execute(
        """
        SELECT * FROM complaints
        WHERE status!='CLOSED'
        ORDER BY created_at DESC
        """
    ).fetchall()
    return render_template("admin_complaints.html", complaints=complaints)

@app.route("/admin/complaint/close/<cid>", methods=["POST"])
@login_required
@admin_required
def close_complaint(cid):
    remark = request.form["remark"]
    db = get_db()

    user_id = db.execute(
        "SELECT user_id FROM complaints WHERE complaint_id=?",
        (cid,)
    ).fetchone()["user_id"]

    db.execute(
        "UPDATE complaints SET status='CLOSED', admin_remark=? WHERE complaint_id=?",
        (remark, cid)
    )

    create_notification(user_id, f"Complaint {cid} CLOSED")
    db.commit()

    return redirect(url_for("admin_complaints"))

# =====================================================
if __name__ == "__main__":
    app.run(debug=True)
