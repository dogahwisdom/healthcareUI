import tkinter as tk
from tkinter import messagebox, ttk
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
import pyodbc
from datetime import datetime, timedelta
import bcrypt
import re
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from typing import Optional, List, Tuple

# Constants
EMAIL_CONFIG = {
    "HOST": "smtp.gmail.com",
    "PORT": 587,
    "USER": "your_email@gmail.com",
    "PASSWORD": "your_email_password"
}

# Configure logging
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class Database:
    """Database connection handler"""

    def __init__(self):
        self.conn = pyodbc.connect(
            "DRIVER={SQL Server};"
            "SERVER=ACTIVEPROGRAMME;"
            "DATABASE=HospitalManagement;"
            "Trusted_Connection=yes"
        )
        self.cursor = self.conn.cursor()

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


class Session:
    """User session management"""

    def __init__(self):
        self.username: Optional[str] = None
        self.role: Optional[str] = None
        self.user_id: Optional[int] = None  # Added user_id for role-based queries

    def clear(self):
        self.username = None
        self.role = None
        self.user_id = None


class HospitalApp:
    def __init__(self, root: ttkb.Window):
        self.root = root
        self.root.title("Hospital Management System")
        self.root.geometry("1200x800")
        self.session = Session()
        self.db = Database()
        self.style = ttkb.Style()
        self.style.theme_use("cosmo")  # Default theme

        self._setup_ui()
        self.show_login()

    def _setup_ui(self):
        """Initialize UI components"""
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=0)
        self.root.grid_rowconfigure(2, weight=0)
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Theme selection
        self.theme_var = tk.StringVar(value="cosmo")
        theme_label = ttkb.Label(self.root, text="Theme:")
        theme_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        theme_combobox = ttkb.Combobox(
            self.root,
            textvariable=self.theme_var,
            values=["cosmo", "litera", "darkly", "superhero", "minty"],
            state="readonly"
        )
        theme_combobox.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        theme_combobox.bind("<<ComboboxSelected>>", self._change_theme)

        # Font Size Control
        self.font_size_var = tk.IntVar(value=12)
        font_size_label = ttkb.Label(self.root, text="Font Size:")
        font_size_label.grid(row=1, column=0, padx=5, pady=(0, 5), sticky="w")
        font_size_scale = ttkb.Scale(
            self.root,
            from_=10,
            to=20,
            variable=self.font_size_var,
            command=self._change_font_size
        )
        font_size_scale.grid(row=1, column=1, padx=5, pady=(0, 5), sticky="ew")

    def _change_theme(self, event=None):
        """Changes the theme of the application."""
        selected_theme = self.theme_var.get()
        self.style.theme_use(selected_theme)
        logging.info(f"Theme changed to: {selected_theme}")
        self.root.update()

    def _change_font_size(self, value: str):
        size = int(float(value))
        self.style.configure(".", font=("Arial", size))
        logging.info(f"Font size changed to: {size}")

    def _create_frame(self, title: str) -> ttkb.Frame:
        """Create and configure a new frame"""
        if hasattr(self, 'current_frame'):
            self.current_frame.destroy()
        frame = ttkb.Frame(self.root, padding=20)
        frame.grid(row=3, column=0, pady=20, padx=20, sticky="nsew")
        ttkb.Label(frame, text=title, font=("Arial", 18, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="n")
        self.current_frame = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        return frame

    def show_login(self):
        frame = self._create_frame("Login")

        ttkb.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = ttkb.Entry(frame)
        self.username_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="Password:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.password_entry = ttkb.Entry(frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        login_button = ttkb.Button(frame, text="Login", command=self._login, bootstyle=SUCCESS)
        login_button.grid(row=3, column=1, pady=10, sticky="w")

        signup_button = ttkb.Button(frame, text="Signup", command=self.show_signup, bootstyle=INFO)
        signup_button.grid(row=4, column=1, pady=5, sticky="w")

        forgot_password_button = ttkb.Button(frame, text="Forgot Password", command=self.show_forgot_password, bootstyle=WARNING)
        forgot_password_button.grid(row=5, column=1, pady=5, sticky="w")

        for child in frame.winfo_children():
            child.grid_configure(padx=5, pady=3)

    def _login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        logging.info(f"Login attempt: {username}")

        try:
            self.db.cursor.execute("SELECT Username, Password, Role, DoctorID FROM Users LEFT JOIN Doctors ON Users.Username = Doctors.DoctorName WHERE Username = ?", (username,))
            user = self.db.cursor.fetchone()

            if user and bcrypt.checkpw(password.encode(), user[1].encode()):
                self.session.username = username
                self.session.role = user[2]
                self.session.user_id = user[3] if user[3] else None  # Set DoctorID for doctors
                logging.info(f"User {username} logged in as {user[2]}")
                self._show_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials")
                logging.warning(f"Failed login attempt: {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Login error: {e}")

    def show_signup(self):
        frame = self._create_frame("Signup")

        fields = [
            ("Username:", "username", ttkb.Entry),
            ("Password:", "password", lambda f: ttkb.Entry(f, show="*")),
            ("Confirm Password:", "confirm", lambda f: ttkb.Entry(f, show="*")),
            ("Role:", "role", lambda f: ttkb.Combobox(f, values=["Admin", "Doctor", "Receptionist"]))
        ]

        self.signup_entries = {}
        for i, (label, key, widget_type) in enumerate(fields, start=1):
            ttkb.Label(frame, text=label).grid(row=i, column=0, padx=10, pady=5, sticky="e")
            widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=5, sticky="w")
            self.signup_entries[key] = widget

        signup_button = ttkb.Button(frame, text="Signup", command=self._signup, bootstyle=SUCCESS)
        signup_button.grid(row=len(fields) + 1, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self.show_login, bootstyle=DANGER)
        back_button.grid(row=len(fields) + 1, column=0, pady=10, sticky="e")

        for child in frame.winfo_children():
            child.grid_configure(padx=5, pady=3)

    def _signup(self):
        data = {k: v.get().strip() for k, v in self.signup_entries.items()}

        if not all(data.values()):
            messagebox.showerror("Error", "All fields required")
            return

        if not re.match(r"^\S{4,}$", data["username"]):
            messagebox.showerror("Error", "Username must be 4+ characters, no spaces")
            return

        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", data["password"]):
            messagebox.showerror("Error", "Password must be 8+ characters with upper, lower, and digit")
            return

        if data["password"] != data["confirm"]:
            messagebox.showerror("Error", "Passwords don't match")
            return

        try:
            self.db.cursor.execute("SELECT Username FROM Users WHERE Username = ?", (data["username"],))
            if self.db.cursor.fetchone():
                messagebox.showerror("Error", "Username exists")
                return

            hashed = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt()).decode()
            self.db.cursor.execute(
                "INSERT INTO Users (Username, Password, Role) VALUES (?, ?, ?)",
                (data["username"], hashed, data["role"])
            )
            self.db.commit()
            messagebox.showinfo("Success", "Signup successful")
            self.show_login()
            logging.info(f"New user: {data['username']} ({data['role']})")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Signup error: {e}")

    def show_forgot_password(self):
        frame = self._create_frame("Forgot Password")

        ttkb.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.forgot_username = ttkb.Entry(frame)
        self.forgot_username.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="Email:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.forgot_email = ttkb.Entry(frame)
        self.forgot_email.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        generate_token_button = ttkb.Button(frame, text="Generate Token", command=self._generate_token, bootstyle=SUCCESS)
        generate_token_button.grid(row=3, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self.show_login, bootstyle=DANGER)
        back_button.grid(row=4, column=1, pady=10, sticky="w")

        for child in frame.winfo_children():
            child.grid_configure(padx=5, pady=3)

    def _generate_token(self):
        username = self.forgot_username.get().strip()
        email = self.forgot_email.get().strip()

        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            messagebox.showerror("Error", "Invalid email")
            return

        try:
            self.db.cursor.execute("SELECT Username FROM Users WHERE Username = ?", (username,))
            if not self.db.cursor.fetchone():
                messagebox.showerror("Error", "Username not found")
                return

            token = secrets.token_hex(16)
            expiry = datetime.now() + timedelta(minutes=10)
            self.db.cursor.execute(
                "INSERT INTO PasswordResetTokens (Username, Token, Expiry) VALUES (?, ?, ?)",
                (username, token, expiry)
            )
            self.db.commit()

            self._send_email(email, token)
            self._show_reset_password(token)
            logging.info(f"Token generated for {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Token generation error: {e}")

    def _send_email(self, email: str, token: str):
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG["USER"]
            msg['To'] = email
            msg['Subject'] = "Password Reset Token"
            msg.attach(MIMEText(f"Your reset token: {token}\nExpires in 10 minutes", 'plain'))

            with smtplib.SMTP(EMAIL_CONFIG["HOST"], EMAIL_CONFIG["PORT"]) as server:
                server.starttls()
                server.login(EMAIL_CONFIG["USER"], EMAIL_CONFIG["PASSWORD"])
                server.send_message(msg)

            messagebox.showinfo("Success", "Token sent to email")
            logging.info(f"Email sent to {email}")
        except Exception as e:
            messagebox.showerror("Error", f"Email error: {e}")
            logging.error(f"Email error: {e}")

    def _show_reset_password(self, token: str):
        frame = self._create_frame("Reset Password")

        ttkb.Label(frame, text="Token:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        token_entry = ttkb.Entry(frame)
        token_entry.insert(0, token)
        token_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="New Password:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.reset_pass = ttkb.Entry(frame, show="*")
        self.reset_pass.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="Confirm:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
        self.reset_confirm = ttkb.Entry(frame, show="*")
        self.reset_confirm.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        reset_button = ttkb.Button(frame, text="Reset", command=lambda: self._reset_password(token), bootstyle=SUCCESS)
        reset_button.grid(row=4, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self.show_login, bootstyle=DANGER)
        back_button.grid(row=4, column=0, pady=10, sticky="e")

        for child in frame.winfo_children():
            child.grid_configure(padx=5, pady=3)

    def _reset_password(self, token: str):
        password = self.reset_pass.get()
        confirm = self.reset_confirm.get()

        if not all([password, confirm]):
            messagebox.showerror("Error", "All fields required")
            return

        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$", password):
            messagebox.showerror("Error", "Password must be 8+ characters with upper, lower, and digit")
            return

        if password != confirm:
            messagebox.showerror("Error", "Passwords don't match")
            return

        try:
            self.db.cursor.execute("SELECT Username, Expiry FROM PasswordResetTokens WHERE Token = ?", (token,))
            token_data = self.db.cursor.fetchone()

            if not token_data or datetime.now() > token_data[1]:
                messagebox.showerror("Error", "Invalid/expired token")
                return

            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            self.db.cursor.execute(
                "UPDATE Users SET Password = ? WHERE Username = ?",
                (hashed, token_data[0])
            )
            self.db.cursor.execute("DELETE FROM PasswordResetTokens WHERE Token = ?", (token,))
            self.db.commit()

            messagebox.showinfo("Success", "Password reset successful")
            self.show_login()
            logging.info(f"Password reset for {token_data[0]}")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Reset error: {e}")

    def _show_dashboard(self):
        frame = self._create_frame(f"{self.session.role} Dashboard")

        actions = {
            "Admin": [
                ("View Patients", self._view_patients, PRIMARY),
                ("Add Patient", self._add_patient, SUCCESS),
                ("View Doctors", self._view_doctors, INFO),
                ("Schedule Appointment", self._schedule_appointment, WARNING),
                ("View Appointments", self._view_appointments, DANGER),
                ("Manage Records", self._manage_records, SECONDARY)
            ],
            "Doctor": [
                ("View My Patients", self._view_doctor_patients, PRIMARY),
                ("View My Appointments", self._view_doctor_appointments, INFO),  # Updated to use the new method
                ("Update Records", self._update_patient_records, SUCCESS)
            ],
            "Receptionist": [
                ("View Patients", self._view_patients, PRIMARY),
                ("Add Patient", self._add_patient, SUCCESS),
                ("Schedule Appointment", self._schedule_appointment, WARNING),
                ("View Appointments", self._view_appointments, INFO)
            ]
        }

        num_actions = len(actions.get(self.session.role, []))
        for i, (text, command, style) in enumerate(actions.get(self.session.role, []), start=1):
            button = ttkb.Button(frame, text=text, command=command, bootstyle=style)
            button.grid(row=i, column=0, columnspan=2, pady=5, sticky="ew")

        logout_button = ttkb.Button(frame, text="Logout", command=self._logout, bootstyle=DARK)
        logout_button.grid(row=num_actions + 1, column=0, columnspan=2, pady=10, sticky="ew")

    def _logout(self):
        self.session.clear()
        self.show_login()
        logging.info("User logged out")

    def _view_patients(self):
        frame = self._create_frame("Patients List")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "DOB", "Gender", "Contact"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Gender", text="Gender")
        tree.heading("Contact", text="Contact")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT PatientID, PatientName, DateOfBirth, Gender, ContactNumber FROM Patients")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View patients error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _add_patient(self):
        frame = self._create_frame("Add Patient")

        fields = [
            ("Name:", "PatientName", ttkb.Entry),
            ("Date of Birth (YYYY-MM-DD):", "DateOfBirth", ttkb.Entry),
            ("Gender:", "Gender", ttkb.Entry),
            ("Contact Number:", "ContactNumber", ttkb.Entry)
        ]

        self.patient_entries = {}
        for i, (label, key, widget_type) in enumerate(fields, start=1):
            label_widget = ttkb.Label(frame, text=label)
            label_widget.grid(row=i, column=0, padx=10, pady=5, sticky="e")
            widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=5, sticky="w")
            self.patient_entries[key] = widget

        add_button = ttkb.Button(frame, text="Add", command=self._save_patient, bootstyle=SUCCESS)
        add_button.grid(row=len(fields) + 1, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=len(fields) + 1, column=0, pady=10, sticky="e")

    def _save_patient(self):
        data = {k: v.get().strip() for k, v in self.patient_entries.items()}

        if not all(data.values()):
            messagebox.showerror("Error", "All fields required")
            return

        if not re.match(r"^[a-zA-Z\s]+$", data["PatientName"]):
            messagebox.showerror("Error", "Invalid Patient Name. Only letters and spaces allowed.")
            return

        if not re.match(r"^\d{4}-\d{2}-\d{2}$", data["DateOfBirth"]):
            messagebox.showerror("Error", "Invalid Date of Birth format. Use YYYY-MM-DD.")
            return

        if not re.match(r"^(Male|Female|Other)$", data["Gender"], re.IGNORECASE):
            messagebox.showerror("Error", "Invalid Gender. Use Male, Female, or Other.")
            return

        if not re.match(r"^\d{3}-\d{3}-\d{4}$", data["ContactNumber"]):
            messagebox.showerror("Error", "Invalid Contact Number format. Use XXX-XXX-XXXX.")
            return

        try:
            dob = datetime.strptime(data["DateOfBirth"], "%Y-%m-%d").date()
            self.db.cursor.execute(
                "EXEC AddPatient @PatientName=?, @DateOfBirth=?, @Gender=?, @ContactNumber=?",
                (data["PatientName"], dob, data["Gender"], data["ContactNumber"])
            )
            self.db.commit()
            messagebox.showinfo("Success", "Patient added successfully")
            self._show_dashboard()
            logging.info(f"Patient added: {data['PatientName']}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"Add patient error: {e}")

    def _view_doctors(self):
        frame = self._create_frame("Doctors List")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "Specialty"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Doctor ID")
        tree.heading("Name", text="Name")
        tree.heading("Specialty", text="Specialty")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT DoctorID, DoctorName, Specialization FROM Doctors")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctors error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _schedule_appointment(self):
        frame = self._create_frame("Schedule Appointment")

        try:
            self.db.cursor.execute("SELECT DoctorID, DoctorName FROM Doctors")
            doctors = self.db.cursor.fetchall()
            doctor_options = [f"{d[1]} (ID: {d[0]})" for d in doctors]
            self.doctor_ids = {d[0]: d[1] for d in doctors}
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch doctors: {e}")
            logging.error(f"Failed to fetch doctors: {e}")
            return

        fields = [
            ("Patient ID:", "PatientID", ttkb.Entry),
            ("Doctor:", "Doctor", ttkb.Combobox, doctor_options),
            ("Date (YYYY-MM-DD):", "AppointmentDate", ttkb.Entry),
            ("Time (HH:MM):", "AppointmentTime", ttkb.Entry)
        ]

        self.appointment_entries = {}
        for i, (label, key, widget_type, *args) in enumerate(fields, start=1):
            label_widget = ttkb.Label(frame, text=label)
            label_widget.grid(row=i, column=0, padx=10, pady=5, sticky="e")
            if widget_type == ttkb.Combobox:
                widget = ttkb.Combobox(frame, values=args[0], state="readonly")
            else:
                widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=5, sticky="w")
            self.appointment_entries[key] = widget

        schedule_button = ttkb.Button(frame, text="Schedule", command=self._save_appointment, bootstyle=SUCCESS)
        schedule_button.grid(row=len(fields) + 1, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=len(fields) + 1, column=0, pady=10, sticky="e")

    def _save_appointment(self):
        data = {k: v.get().strip() for k, v in self.appointment_entries.items()}

        if not all(data.values()):
            messagebox.showerror("Error", "All fields required")
            return

        if not re.match(r"^\d+$", data["PatientID"]):
            messagebox.showerror("Error", "Invalid Patient ID. Must be numeric.")
            return

        if not re.match(r"^\d{4}-\d{2}-\d{2}$", data["AppointmentDate"]):
            messagebox.showerror("Error", "Invalid Date format. Use YYYY-MM-DD.")
            return

        if not re.match(r"^\d{2}:\d{2}$", data["AppointmentTime"]):
            messagebox.showerror("Error", "Invalid Time format. Use HH:MM.")
            return

        try:
            doctor_id = int(data["Doctor"].split("(ID: ")[1][:-1])
            appt_datetime = datetime.strptime(f"{data['AppointmentDate']} {data['AppointmentTime']}", "%Y-%m-%d %H:%M")
            self.db.cursor.execute(
                "INSERT INTO Appointments (PatientID, DoctorID, AppointmentDate) VALUES (?, ?, ?)",
                (data["PatientID"], doctor_id, appt_datetime)
            )
            self.db.commit()
            messagebox.showinfo("Success", "Appointment scheduled")
            self._show_dashboard()
            logging.info(f"Appointment scheduled: Patient {data['PatientID']} with Doctor {doctor_id}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
            logging.error(f"Schedule appointment error: {e}")

    def _view_appointments(self):
        frame = self._create_frame("Appointments List")
        tree = ttk.Treeview(frame, columns=("ID", "Patient", "Doctor", "Date", "Status"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Appointment ID")
        tree.heading("Patient", text="Patient ID")
        tree.heading("Doctor", text="Doctor ID")
        tree.heading("Date", text="Date")
        tree.heading("Status", text="Status")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT AppointmentID, PatientID, DoctorID, AppointmentDate, Status FROM Appointments")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View appointments error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _view_doctor_patients(self):
        frame = self._create_frame("My Patients")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "DOB", "Contact"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Contact", text="Contact")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("""
                SELECT DISTINCT p.PatientID, p.PatientName, p.DateOfBirth, p.ContactNumber
                FROM Patients p
                JOIN Appointments a ON p.PatientID = a.PatientID
                JOIN Doctors d ON a.DoctorID = d.DoctorID
                WHERE d.DoctorID = ?
            """, (self.session.user_id,))
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctor patients error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _view_doctor_appointments(self):
        frame = self._create_frame("My Appointments")
        tree = ttk.Treeview(frame, columns=("ID", "Patient", "Date", "Status"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Appointment ID")
        tree.heading("Patient", text="Patient ID")
        tree.heading("Date", text="Date")
        tree.heading("Status", text="Status")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("""
                SELECT AppointmentID, PatientID, AppointmentDate, Status
                FROM Appointments
                WHERE DoctorID = ?
            """, (self.session.user_id,))
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctor appointments error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _update_patient_records(self):
        frame = self._create_frame("Update Patient Records")
        ttkb.Label(frame, text="Patient ID:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.patient_id_entry = ttkb.Entry(frame)
        self.patient_id_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="Diagnosis:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.diagnosis_entry = ttkb.Entry(frame)
        self.diagnosis_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        ttkb.Label(frame, text="Treatment:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
        self.treatment_entry = ttkb.Entry(frame)
        self.treatment_entry.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        update_button = ttkb.Button(frame, text="Update", command=self._save_medical_record, bootstyle=SUCCESS)
        update_button.grid(row=4, column=1, pady=10, sticky="w")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=4, column=0, pady=10, sticky="e")

    def _save_medical_record(self):
        patient_id = self.patient_id_entry.get().strip()
        diagnosis = self.diagnosis_entry.get().strip()
        treatment = self.treatment_entry.get().strip()

        if not all([patient_id, diagnosis, treatment]):
            messagebox.showerror("Error", "All fields required")
            return

        try:
            self.db.cursor.execute(
                "INSERT INTO MedicalRecords (PatientID, DoctorID, Diagnosis, Treatment, RecordDate) VALUES (?, ?, ?, ?, ?)",
                (patient_id, self.session.user_id, diagnosis, treatment, datetime.now())
            )
            self.db.commit()
            messagebox.showinfo("Success", "Medical record updated")
            self._show_dashboard()
            logging.info(f"Medical record updated for Patient {patient_id}")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Update medical record error: {e}")

    def _manage_records(self):
        frame = self._create_frame("Manage Medical Records")
        tree = ttk.Treeview(frame, columns=("ID", "Patient", "Doctor", "Diagnosis", "Treatment", "Date"), show="headings", bootstyle="primary")
        tree.heading("ID", text="Record ID")
        tree.heading("Patient", text="Patient ID")
        tree.heading("Doctor", text="Doctor ID")
        tree.heading("Diagnosis", text="Diagnosis")
        tree.heading("Treatment", text="Treatment")
        tree.heading("Date", text="Date")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT RecordID, PatientID, DoctorID, Diagnosis, Treatment, RecordDate FROM MedicalRecords")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View medical records error: {e}")

        back_button = ttkb.Button(frame, text="Back", command=self._show_dashboard, bootstyle=DANGER)
        back_button.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")


if __name__ == "__main__":
    root = ttkb.Window()
    app = HospitalApp(root)
    root.mainloop()