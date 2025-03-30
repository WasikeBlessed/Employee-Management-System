from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory  # type: ignore
from flask_pymongo import PyMongo  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore
from werkzeug.utils import secure_filename  # type: ignore
from bson.objectid import ObjectId  # type: ignore
from datetime import datetime
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import secrets
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Replace with a secure key

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/EMS"
mongo = PyMongo(app)

# Upload Folder Configuration
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'csv'}

# Email Configuration
SENDER_EMAIL = "jblessedwasike@gmail.com"
SENDER_PASSWORD = "znrksupjchuucptg"  # App Password without spaces
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Utility to check login and role
def login_required(role=None):
    if "user_id" not in session:
        flash("Please log in first!", "error")
        return redirect(url_for("login"))
    if role and session.get("role") != role:
        flash("Unauthorized access!", "error")
        return redirect(url_for("login"))

# Log system activities
def log_action(user_id, action, details={}):
    mongo.db.system_logs.insert_one({
        "user_id": user_id,
        "action": action,
        "timestamp": datetime.utcnow(),
        **details
    })

# Send reset email function
def send_reset_email(email, token):
    reset_link = f"http://localhost:5000/reset-password?token={token}"
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = email
    msg["Subject"] = "Password Reset Request"
    body = f"Click this link to reset your password: {reset_link}\nThis link expires in 1 hour."
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        flash(f"Error sending reset email: {str(e)}", "error")
        return False

# Send permission notification email
def send_permission_notification(email, permission, status):
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = email
    msg["Subject"] = f"Permission Request {status}"
    body = f"Your request for '{permission}' permission has been {status.lower()} by HR."
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        flash(f"Error sending notification: {str(e)}", "error")
        return False

# Login Route
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            flash("Email and password are required!", "error")
            return render_template("login.html")

        try:
            user = mongo.db.users.find_one({"email": email})
            if user:
                if check_password_hash(user["password"], password):
                    session["user_id"] = str(user["_id"])
                    session["role"] = user["role"]
                    session["username"] = user["name"]
                    if user["role"] == "Admin":
                        return redirect(url_for("admin_dashboard"))
                    elif user["role"] == "Employee":
                        return redirect(url_for("employee_dashboard"))
                    elif user["role"] == "HR Manager":
                        return redirect(url_for("hr_dashboard"))
                    else:
                        flash("Invalid role assigned. Contact admin.", "error")
                else:
                    flash("Invalid password!", "error")
            else:
                flash("Email not found!", "error")
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")

    return render_template("login.html")

# Forgot Password
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = mongo.db.users.find_one({"email": email})

        if not user:
            flash("Email not found!", "error")
            return redirect(url_for("forgot_password"))

        reset_token = secrets.token_hex(16)
        reset_token_expiry = int(time.time()) + 3600
        mongo.db.users.update_one(
            {"email": email},
            {"$set": {"reset_token": reset_token, "reset_token_expiry": reset_token_expiry}}
        )

        if send_reset_email(email, reset_token):
            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for("login"))
        else:
            return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")

# Reset Password
@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token")
    if not token:
        flash("No reset token provided.", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        password = request.form["password"]
        confirm_password = request.form["confirm-password"]
        token = request.form["token"]

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template("reset_password.html", token=token)

        user = mongo.db.users.find_one({
            "reset_token": token,
            "reset_token_expiry": {"$gt": int(time.time())}
        })

        if not user:
            flash("Invalid or expired reset link!", "error")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password)
        mongo.db.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"password": hashed_password, "reset_token": None, "reset_token_expiry": None}}
        )
        flash("Password reset successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)

# Signup
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        role = request.form["role"]

        if mongo.db.users.find_one({"email": email}):
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": role,
            "phone": "",
            "emergency_contact": "",
            "job_title": "",
            "department": "",
            "employment_status": "Active",
            "leave_balance": {"sick": 10, "vacation": 15},
            "permissions": ""  # Initialize permissions
        })
        flash("Account created successfully! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("sign_up.html")

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# Employee: Request Permission
@app.route("/request_permission", methods=["GET", "POST"])
def request_permission():
    login_required("Employee")
    if request.method == "POST":
        permission = request.form["permission"]
        user_id = session["user_id"]

        existing_request = mongo.db.permission_requests.find_one({
            "user_id": user_id,
            "permission": permission,
            "status": "Pending"
        })
        if existing_request:
            flash("You already have a pending request for this permission!", "error")
            return redirect(url_for("request_permission"))

        mongo.db.permission_requests.insert_one({
            "user_id": user_id,
            "permission": permission,
            "status": "Pending",
            "submitted_at": datetime.utcnow()
        })
        flash("Permission request submitted successfully!", "success")
        return redirect(url_for("employee_dashboard"))

    return render_template("request_permission.html")

# HR Manager: Manage Permission Requests
@app.route("/manage_permissions", methods=["GET", "POST"])
def manage_permissions():
    login_required("HR Manager")
    if request.method == "POST":
        request_id = request.form["request_id"]
        action = request.form["action"]
        permission_request = mongo.db.permission_requests.find_one({"_id": ObjectId(request_id)})

        if permission_request:
            user = mongo.db.users.find_one({"_id": ObjectId(permission_request["user_id"])})
            if action == "approve":
                current_permissions = user.get("permissions", "")
                permission_list = current_permissions.split(",") if current_permissions else []
                if permission_request["permission"] not in permission_list:
                    permission_list.append(permission_request["permission"])
                new_permissions = ",".join(permission_list)
                mongo.db.users.update_one(
                    {"_id": ObjectId(permission_request["user_id"])},
                    {"$set": {"permissions": new_permissions}}
                )
                mongo.db.permission_requests.update_one(
                    {"_id": ObjectId(request_id)},
                    {"$set": {"status": "Approved", "updated_at": datetime.utcnow()}}
                )
                flash(f"Permission '{permission_request['permission']}' approved for {user['name']}.", "success")
                send_permission_notification(user["email"], permission_request["permission"], "Approved")
            elif action == "deny":
                mongo.db.permission_requests.update_one(
                    {"_id": ObjectId(request_id)},
                    {"$set": {"status": "Denied", "updated_at": datetime.utcnow()}}
                )
                flash(f"Permission '{permission_request['permission']}' denied for {user['name']}.", "success")
                send_permission_notification(user["email"], permission_request["permission"], "Denied")

        return redirect(url_for("manage_permissions"))

    pending_requests = list(mongo.db.permission_requests.find({"status": "Pending"}))
    for req in pending_requests:
        user = mongo.db.users.find_one({"_id": ObjectId(req["user_id"])})
        req["user_name"] = user["name"] if user else "Unknown"

    return render_template("manage_permissions.html", requests=pending_requests)

# Admin Dashboard
@app.route("/admin_dashboard")
def admin_dashboard():
    login_required("Admin")
    total_users = mongo.db.users.count_documents({})
    employees_count = mongo.db.users.count_documents({"role": "Employee"})
    hr_count = mongo.db.users.count_documents({"role": "HR Manager"})
    return render_template("admin_dashboard.html", total_users=total_users, employees_count=employees_count, hr_count=hr_count)

# Manage Users
@app.route("/manage_users")
def manage_users():
    login_required("Admin")
    users = list(mongo.db.users.find())
    return render_template("manage_users.html", users=users)

# Update User
@app.route("/update_user/<user_id>", methods=["GET", "POST"])
def update_user(user_id):
    login_required("Admin")
    user = mongo.db.users.find_one({"_id": ObjectId(user_id)})

    if request.method == "POST":
        role = request.form["role"]
        permissions = request.form["permissions"].strip()
        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": role, "permissions": permissions}}
        )
        log_action(session["user_id"], "Updated User", {"updated_user_id": user_id, "new_role": role, "permissions": permissions})
        flash("User updated successfully!", "success")
        return redirect(url_for("manage_users"))

    return render_template("update_user.html", user=user)

# Delete User
@app.route("/delete_user/<user_id>")
def delete_user(user_id):
    login_required("Admin")
    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    log_action(session["user_id"], "Deleted User", {"deleted_user_id": user_id})
    flash("User deleted successfully!", "success")
    return redirect(url_for("manage_users"))

# Assign Roles
@app.route("/assign_roles", methods=["GET", "POST"])
def assign_roles():
    login_required("Admin")
    if request.method == "POST":
        user_id = request.form["user_id"]
        role = request.form["role"]
        permissions = request.form["permissions"]
        mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": role, "permissions": permissions}}
        )
        log_action(session["user_id"], "Assigned Role", {"user_id": user_id, "new_role": role, "permissions": permissions})
        flash("Role updated successfully!", "success")
        return redirect(url_for("assign_roles"))

    users = list(mongo.db.users.find())
    return render_template("assign_roles.html", users=users)

# System Activities
@app.route("/system_activities")
def system_activities():
    login_required("Admin")
    logs = list(mongo.db.system_logs.find().sort("timestamp", -1))
    return render_template("system_activities.html", logs=logs)

# Generate Reports
@app.route("/generate_reports")
def generate_reports():
    login_required("Admin")
    report = mongo.db.users.aggregate([
        {"$group": {"_id": "$role", "count": {"$sum": 1}}}
    ])
    return render_template("generate_reports.html", report=report)

# HR Dashboard
@app.route("/hr_dashboard")
def hr_dashboard():
    login_required("HR Manager")
    pending_requests_count = mongo.db.permission_requests.count_documents({"status": "Pending"})
    return render_template("hr_dashboard.html", pending_requests_count=pending_requests_count)

# Add Employee
@app.route("/add_employee", methods=["GET", "POST"])
def add_employee():
    login_required("HR Manager")
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        if mongo.db.users.find_one({"email": email}):
            flash("Email already registered.", "error")
            return redirect(url_for("add_employee"))

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": "Employee",
            "permissions": ""
        })
        flash("Employee added successfully!", "success")
        return redirect(url_for("view_employees"))

    return render_template("add_employee.html")

# View Employees
@app.route("/view_employees", methods=["GET"])
def view_employees():
    login_required("HR Manager")
    search_query = request.args.get("search", "").strip()
    sort_by = request.args.get("sort_by", "name")
    sort_order = int(request.args.get("sort_order", 1))

    query = {"role": "Employee"}
    if search_query:
        query["$or"] = [
            {"name": {"$regex": search_query, "$options": "i"}},
            {"email": {"$regex": search_query, "$options": "i"}},
            {"department": {"$regex": search_query, "$options": "i"}}
        ]

    employees = list(mongo.db.users.find(query, {"name": 1, "email": 1, "department": 1, "phone": 1, "_id": 0}).sort(sort_by, sort_order))
    return render_template("view_employees.html", employees=employees, search_query=search_query, sort_by=sort_by, sort_order=sort_order)

# HR Reports
@app.route("/hr_reports")
def hr_reports():
    login_required("HR Manager")
    return render_template("hr_reports.html")

@app.route("/upload_report", methods=["POST"])
def upload_report():
    login_required("HR Manager")
    if "report_file" not in request.files:
        flash("No file part!", "error")
        return redirect(url_for("hr_reports"))

    file = request.files["report_file"]
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)
        mongo.db.hr_reports.insert_one({"filename": filename, "file_path": file_path})
        flash("Report uploaded successfully!", "success")
    else:
        flash("Invalid file type! Allowed: pdf, docx, csv.", "error")

    return redirect(url_for("hr_reports"))

@app.route("/send_report", methods=["POST"])
def send_report():
    login_required("HR Manager")
    recipient_email = request.form["recipient_email"]
    latest_report = mongo.db.hr_reports.find_one(sort=[("_id", -1)])

    if not latest_report:
        flash("No reports available to send.", "error")
        return redirect(url_for("hr_reports"))

    file_path = latest_report["file_path"]
    filename = latest_report["filename"]

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = recipient_email
    msg["Subject"] = "HR Report Submission"
    msg.attach(MIMEText("Please find the attached HR report.", "plain"))

    with open(file_path, "rb") as attachment:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")
        msg.attach(part)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())
        server.quit()
        flash("Report sent successfully!", "success")
    except Exception as e:
        flash(f"Error sending email: {str(e)}", "error")

    return redirect(url_for("hr_reports"))

# HR Employee Reports
@app.route("/hr_employee_reports", methods=["GET", "POST"])
def hr_employee_reports():
    login_required("HR Manager")
    if request.method == "POST":
        report_title = request.form["report_title"]
        report_description = request.form["report_description"]
        submitted_by = session["username"]
        file_path = None

        if "report_file" in request.files:
            file = request.files["report_file"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)

        mongo.db.employee_reports.insert_one({
            "title": report_title,
            "description": report_description,
            "submitted_by": submitted_by,
            "file_path": file_path
        })
        flash("Report submitted successfully!", "success")
        return redirect(url_for("hr_employee_reports"))

    reports = list(mongo.db.employee_reports.find())
    return render_template("hr_employee_reports.html", reports=reports)

# HR Notifications
@app.route("/hr_notifications")
def hr_notifications():
    login_required("HR Manager")
    notifications = list(mongo.db.notifications.find({"recipient_id": {"$in": ["all", session["user_id"]]}}))
    complaints = list(mongo.db.requests.find())
    leaves = list(mongo.db.leaves.find())
    shift_requests = list(mongo.db.shift_requests.find())
    messages = list(mongo.db.messages.find({"recipient_id": session["user_id"]}))
    resignations = list(mongo.db.resignations.find())
    
    for item in notifications + complaints + leaves + shift_requests + messages + resignations:
        if "user_id" in item:
            user = mongo.db.users.find_one({"_id": ObjectId(item["user_id"])})
            item["user_name"] = user["name"] if user else "Unknown"
        if "sender_id" in item:
            sender = mongo.db.users.find_one({"_id": ObjectId(item["sender_id"])})
            item["sender_name"] = sender["name"] if sender else "Unknown"
    
    return render_template("hr_notifications.html", 
                         notifications=notifications,
                         complaints=complaints,
                         leaves=leaves,
                         shift_requests=shift_requests,
                         messages=messages,
                         resignations=resignations)

# Serve Uploaded Files
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# Employee Dashboard
@app.route("/employee_dashboard")
def employee_dashboard():
    login_required("Employee")
    user = mongo.db.users.find_one({"_id": ObjectId(session["user_id"])})
    all_requests = list(mongo.db.permission_requests.find({"user_id": session["user_id"]}).sort("submitted_at", -1))
    return render_template("employee_dashboard.html", user=user, requests=all_requests)

# Employee: View Permission Status
@app.route("/permission_status")
def permission_status():
    login_required("Employee")
    user = mongo.db.users.find_one({"_id": ObjectId(session["user_id"])})
    all_requests = list(mongo.db.permission_requests.find({"user_id": session["user_id"]}).sort("submitted_at", -1))
    return render_template("permission_status.html", user=user, requests=all_requests)

# Employee Profile
@app.route("/profile", methods=["GET", "POST"])
def profile():
    login_required("Employee")
    user = mongo.db.users.find_one({"_id": ObjectId(session["user_id"])})
    if request.method == "POST":
        phone = request.form["phone"]
        emergency_contact = request.form["emergency_contact"]
        mongo.db.users.update_one(
            {"_id": ObjectId(session["user_id"])},
            {"$set": {"phone": phone, "emergency_contact": emergency_contact}}
        )
        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)

# Manage Attendance & Leaves
@app.route("/attendance_leaves", methods=["GET", "POST"])
def attendance_leaves():
    login_required("Employee")
    user = mongo.db.users.find_one({"_id": ObjectId(session["user_id"])})
    leaves = list(mongo.db.leaves.find({"user_id": session["user_id"]}))
    if request.method == "POST":
        leave_type = request.form["leave_type"]
        start_date = request.form["start_date"]
        end_date = request.form["end_date"]
        mongo.db.leaves.insert_one({
            "user_id": session["user_id"],
            "leave_type": leave_type,
            "start_date": start_date,
            "end_date": end_date,
            "status": "Pending",
            "submitted_at": datetime.utcnow()
        })
        flash("Leave request submitted!", "success")
        return redirect(url_for("attendance_leaves"))
    return render_template("attendance_leaves.html", user=user, leaves=leaves)

# View Salary Details
@app.route("/salary_details")
def salary_details():
    login_required("Employee")
    salaries = list(mongo.db.salaries.find({"user_id": session["user_id"]}))
    return render_template("salary_details.html", salaries=salaries)

# Manage Work Schedule & Shift Details
@app.route("/work_schedule", methods=["GET", "POST"])
def work_schedule():
    login_required("Employee")
    schedules = list(mongo.db.schedules.find({"user_id": session["user_id"]}))
    if request.method == "POST":
        shift_request = request.form["shift_request"]
        mongo.db.shift_requests.insert_one({
            "user_id": session["user_id"],
            "request": shift_request,
            "status": "Pending",
            "submitted_at": datetime.utcnow()
        })
        flash("Shift change request submitted!", "success")
        return redirect(url_for("work_schedule"))
    return render_template("work_schedule.html", schedules=schedules)

# Receive Notifications & Announcements
@app.route("/notifications")
def notifications():
    login_required("Employee")
    notifications = list(mongo.db.notifications.find({"$or": [{"recipient_id": session["user_id"]}, {"recipient_id": "all"}]}))
    return render_template("notifications.html", notifications=notifications)

# Submit Requests & Complaints
@app.route("/requests_complaints", methods=["GET", "POST"])
def requests_complaints():
    login_required("Employee")
    if request.method == "POST":
        request_type = request.form["request_type"]
        description = request.form["description"]
        mongo.db.requests.insert_one({
            "user_id": session["user_id"],
            "type": request_type,
            "description": description,
            "status": "Pending",
            "submitted_at": datetime.utcnow()
        })
        flash("Request/Complaint submitted!", "success")
        return redirect(url_for("requests_complaints"))
    requests = list(mongo.db.requests.find({"user_id": session["user_id"]}))
    return render_template("requests_complaints.html", requests=requests)

# Performance Tracking & Feedback
@app.route("/performance")
def performance():
    login_required("Employee")
    feedbacks = list(mongo.db.feedbacks.find({"user_id": session["user_id"]}))
    return render_template("performance.html", feedbacks=feedbacks)

# Training & Development
@app.route("/training", methods=["GET", "POST"])
def training():
    login_required("Employee")
    trainings = list(mongo.db.trainings.find({"$or": [{"user_id": session["user_id"]}, {"user_id": "all"}]}))
    if request.method == "POST":
        training_id = request.form["training_id"]
        mongo.db.user_trainings.insert_one({
            "user_id": session["user_id"],
            "training_id": training_id,
            "status": "Enrolled",
            "enrolled_at": datetime.utcnow()
        })
        flash("Enrolled in training!", "success")
        return redirect(url_for("training"))
    user_trainings = list(mongo.db.user_trainings.find({"user_id": session["user_id"]}))
    return render_template("training.html", trainings=trainings, user_trainings=user_trainings)

# Team Collaboration & Messaging
@app.route("/messaging", methods=["GET", "POST"])
def messaging():
    login_required("Employee")
    if request.method == "POST":
        recipient_id = request.form["recipient_id"]
        message = request.form["message"]
        mongo.db.messages.insert_one({
            "sender_id": session["user_id"],
            "recipient_id": recipient_id,
            "message": message,
            "sent_at": datetime.utcnow()
        })
        flash("Message sent!", "success")
        return redirect(url_for("messaging"))
    messages = list(mongo.db.messages.find({"$or": [{"sender_id": session["user_id"]}, {"recipient_id": session["user_id"]}]}))
    users = list(mongo.db.users.find({"_id": {"$ne": ObjectId(session["user_id"])}}))
    return render_template("messaging.html", messages=messages, users=users)

# Submit Resignation & Exit Process
@app.route("/resignation", methods=["GET", "POST"])
def resignation():
    login_required("Employee")
    resignation = mongo.db.resignations.find_one({"user_id": session["user_id"]})
    
    if request.method == "POST":
        if resignation:
            flash("You have already submitted a resignation!", "error")
        else:
            reason = request.form["reason"]
            file = request.files.get("resignation_file")
            file_name = None
            
            if file and allowed_file(file.filename):
                file_name = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], file_name))
            
            mongo.db.resignations.insert_one({
                "user_id": session["user_id"],
                "reason": reason,
                "file_name": file_name,
                "status": "Pending",
                "submitted_at": datetime.utcnow()
            })
            flash("Resignation submitted successfully!", "success")
            resignation = mongo.db.resignations.find_one({"user_id": session["user_id"]})
    
    return render_template("resignation.html", resignation=resignation)

if __name__ == "__main__":
    app.run(debug=True, port=5000)