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

    def clear(self):
        self.username = None
        self.role = None


class HospitalApp:
    def __init__(self, root: ttkb.Window):
        self.root = root
        self.root.title("Hospital Management System")
        self.root.geometry("1200x800")
        self.session = Session()
        self.db = Database()
        self.style = ttkb.Style()

        self._setup_ui()
        self.show_login()

    def _setup_ui(self):
        """Initialize UI components"""
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=0)
        self.root.grid_rowconfigure(2, weight=0)
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.theme_var = tk.StringVar(value="cosmo")
        ttkb.Combobox(
            self.root,
            textvariable=self.theme_var,
            values=["cosmo", "litera", "darkly", "superhero", "minty"],
            state="readonly"
        ).grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.theme_var.trace("w", self._change_theme)

        self.font_size_var = tk.IntVar(value=12)
        ttkb.Label(self.root, text="Font Size:").grid(row=1, column=0, padx=10, pady=(0, 5), sticky="w")
        ttkb.Scale(
            self.root,
            from_=10,
            to=20,
            variable=self.font_size_var,
            command=self._change_font_size
        ).grid(row=2, column=0, padx=10, pady=(0, 5), sticky="ew")

    def _change_theme(self, *args):
        self.style.theme_use(self.theme_var.get())
        logging.info(f"Theme changed to: {self.theme_var.get()}")

    def _change_font_size(self, value: str):
        size = int(float(value))
        self.style.configure(".", font=("Arial", size))
        logging.info(f"Font size changed to: {size}")

    def _create_frame(self, title: str) -> ttkb.Frame:
        """Create and configure a new frame"""
        if hasattr(self, 'current_frame'):
            self.current_frame.destroy()
        frame = ttkb.Frame(self.root)
        frame.grid(row=3, column=0, pady=50, sticky="nsew")
        ttkb.Label(frame, text=title, font=("Arial", 16)).grid(row=0, column=0, columnspan=2, pady=20)
        self.current_frame = frame
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        return frame

    def show_login(self):
        frame = self._create_frame("Login")

        ttkb.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.username_entry = ttkb.Entry(frame)
        self.username_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.password_entry = ttkb.Entry(frame, show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        ttkb.Button(frame, text="Login", command=self._login, bootstyle=SUCCESS).grid(row=3, column=1, pady=10,
                                                                                      sticky="w")
        ttkb.Button(frame, text="Signup", command=self.show_signup, bootstyle=INFO).grid(row=4, column=1, pady=10,
                                                                                         sticky="w")
        ttkb.Button(frame, text="Forgot Password", command=self.show_forgot_password,
                    bootstyle=WARNING).grid(row=5, column=1, pady=10, sticky="w")

    def _login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        logging.info(f"Login attempt: {username}")

        try:
            self.db.cursor.execute("SELECT Password, Role FROM Users WHERE Username = ?", (username,))
            user = self.db.cursor.fetchone()

            if user and bcrypt.checkpw(password.encode(), user[0].encode()):
                self.session.username = username
                self.session.role = user[1]
                logging.info(f"User {username} logged in as {user[1]}")
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
            ttkb.Label(frame, text=label).grid(row=i, column=0, padx=10, pady=10, sticky="e")
            widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=10, sticky="w")
            self.signup_entries[key] = widget

        ttkb.Button(frame, text="Signup", command=self._signup, bootstyle=SUCCESS).grid(row=5, column=1, pady=10,
                                                                                        sticky="w")
        ttkb.Button(frame, text="Back", command=self.show_login, bootstyle=DANGER).grid(row=5, column=0, pady=10,
                                                                                        sticky="e")

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

        ttkb.Label(frame, text="Username:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.forgot_username = ttkb.Entry(frame)
        self.forgot_username.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Email:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.forgot_email = ttkb.Entry(frame)
        self.forgot_email.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        ttkb.Button(frame, text="Generate Token", command=self._generate_token,
                    bootstyle=SUCCESS).grid(row=3, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self.show_login,
                    bootstyle=DANGER).grid(row=4, column=1, pady=10, sticky="w")

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

        ttkb.Label(frame, text="Token:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        token_entry = ttkb.Entry(frame)
        token_entry.insert(0, token)
        token_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="New Password:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.reset_pass = ttkb.Entry(frame, show="*")
        self.reset_pass.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Confirm:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.reset_confirm = ttkb.Entry(frame, show="*")
        self.reset_confirm.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        ttkb.Button(frame, text="Reset", command=lambda: self._reset_password(token),
                    bootstyle=SUCCESS).grid(row=4, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self.show_login,
                    bootstyle=DANGER).grid(row=4, column=0, pady=10, sticky="e")

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
                ("View Appointments", self._view_doctor_appointments, INFO),
                ("Update Records", self._update_patient_records, SUCCESS)
            ],
            "Receptionist": [
                ("View Patients", self._view_patients, PRIMARY),
                ("Add Patient", self._add_patient, SUCCESS),
                ("Schedule Appointment", self._schedule_appointment, WARNING),
                ("View Appointments", self._view_appointments, INFO)
            ]
        }

        for i, (text, command, style) in enumerate(actions.get(self.session.role, []), start=1):
            ttkb.Button(frame, text=text, command=command,
                        bootstyle=style).grid(row=i, column=0, columnspan=2, pady=10, sticky="ew")

        ttkb.Button(frame, text="Logout", command=self._logout,
                    bootstyle=DARK).grid(row=len(actions.get(self.session.role, [])) + 1,
                                         column=0, columnspan=2, pady=10, sticky="ew")

    def _logout(self):
        self.session.clear()
        self.show_login()
        logging.info("User logged out")

    def _view_patients(self):
        frame = self._create_frame("Patients List")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "DOB", "Contact"), show="headings")
        tree.heading("ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Contact", text="Contact")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT PatientID, Name, DOB, Contact FROM Patients")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View patients error: {e}")

        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _add_patient(self):
        frame = self._create_frame("Add Patient")

        fields = [
            ("Name:", "name", ttkb.Entry),
            ("Date of Birth (YYYY-MM-DD):", "dob", ttkb.Entry),
            ("Contact:", "contact", ttkb.Entry),
            ("Address:", "address", ttkb.Entry)
        ]

        self.patient_entries = {}
        for i, (label, key, widget_type) in enumerate(fields, start=1):
            ttkb.Label(frame, text=label).grid(row=i, column=0, padx=10, pady=10, sticky="e")
            widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=10, sticky="w")
            self.patient_entries[key] = widget

        ttkb.Button(frame, text="Add", command=self._save_patient,
                    bootstyle=SUCCESS).grid(row=5, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=5, column=0, pady=10, sticky="e")

    def _save_patient(self):
        data = {k: v.get().strip() for k, v in self.patient_entries.items()}

        if not all(data.values()):
            messagebox.showerror("Error", "All fields required")
            return

        try:
            dob = datetime.strptime(data["dob"], "%Y-%m-%d")
            self.db.cursor.execute(
                "INSERT INTO Patients (Name, DOB, Contact, Address) VALUES (?, ?, ?, ?)",
                (data["name"], dob, data["contact"], data["address"])
            )
            self.db.commit()
            messagebox.showinfo("Success", "Patient added successfully")
            self._show_dashboard()
            logging.info(f"Patient added: {data['name']}")
        except ValueError:
            messagebox.showerror("Error", "Invalid date format (use YYYY-MM-DD)")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Add patient error: {e}")

    def _view_doctors(self):
        frame = self._create_frame("Doctors List")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "Specialty"), show="headings")
        tree.heading("ID", text="Doctor ID")
        tree.heading("Name", text="Name")
        tree.heading("Specialty", text="Specialty")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT DoctorID, Name, Specialty FROM Doctors")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctors error: {e}")

        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _schedule_appointment(self):
        frame = self._create_frame("Schedule Appointment")

        fields = [
            ("Patient ID:", "patient_id", ttkb.Entry),
            ("Doctor ID:", "doctor_id", ttkb.Entry),
            ("Date (YYYY-MM-DD):", "date", ttkb.Entry),
            ("Time (HH:MM):", "time", ttkb.Entry)
        ]

        self.appointment_entries = {}
        for i, (label, key, widget_type) in enumerate(fields, start=1):
            ttkb.Label(frame, text=label).grid(row=i, column=0, padx=10, pady=10, sticky="e")
            widget = widget_type(frame)
            widget.grid(row=i, column=1, padx=10, pady=10, sticky="w")
            self.appointment_entries[key] = widget

        ttkb.Button(frame, text="Schedule", command=self._save_appointment,
                    bootstyle=SUCCESS).grid(row=5, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=5, column=0, pady=10, sticky="e")

    def _save_appointment(self):
        data = {k: v.get().strip() for k, v in self.appointment_entries.items()}

        if not all(data.values()):
            messagebox.showerror("Error", "All fields required")
            return

        try:
            appt_datetime = datetime.strptime(f"{data['date']} {data['time']}", "%Y-%m-%d %H:%M")
            self.db.cursor.execute(
                "INSERT INTO Appointments (PatientID, DoctorID, AppointmentDate) VALUES (?, ?, ?)",
                (data["patient_id"], data["doctor_id"], appt_datetime)
            )
            self.db.commit()
            messagebox.showinfo("Success", "Appointment scheduled")
            self._show_dashboard()
            logging.info(f"Appointment scheduled: Patient {data['patient_id']} with Doctor {data['doctor_id']}")
        except ValueError:
            messagebox.showerror("Error", "Invalid date/time format (use YYYY-MM-DD HH:MM)")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Schedule appointment error: {e}")

    def _view_appointments(self):
        frame = self._create_frame("Appointments List")
        tree = ttk.Treeview(frame, columns=("ID", "Patient", "Doctor", "Date"), show="headings")
        tree.heading("ID", text="Appointment ID")
        tree.heading("Patient", text="Patient ID")
        tree.heading("Doctor", text="Doctor ID")
        tree.heading("Date", text="Date")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("SELECT AppointmentID, PatientID, DoctorID, AppointmentDate FROM Appointments")
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View appointments error: {e}")

        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _view_doctor_patients(self):
        frame = self._create_frame("My Patients")
        tree = ttk.Treeview(frame, columns=("ID", "Name", "DOB", "Contact"), show="headings")
        tree.heading("ID", text="Patient ID")
        tree.heading("Name", text="Name")
        tree.heading("DOB", text="Date of Birth")
        tree.heading("Contact", text="Contact")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("""
                SELECT DISTINCT p.PatientID, p.Name, p.DOB, p.Contact 
                FROM Patients p
                JOIN Appointments a ON p.PatientID = a.PatientID
                JOIN Doctors d ON a.DoctorID = d.DoctorID
                WHERE d.Username = ?
            """, (self.session.username,))
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctor patients error: {e}")

        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _view_doctor_appointments(self):
        frame = self._create_frame("My Appointments")
        tree = ttk.Treeview(frame, columns=("ID", "Patient", "Date"), show="headings")
        tree.heading("ID", text="Appointment ID")
        tree.heading("Patient", text="Patient ID")
        tree.heading("Date", text="Date")
        tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

        try:
            self.db.cursor.execute("""
                SELECT a.AppointmentID, a.PatientID, a.AppointmentDate 
                FROM Appointments a
                JOIN Doctors d ON a.DoctorID = d.DoctorID
                WHERE d.Username = ?
            """, (self.session.username,))
            for row in self.db.cursor.fetchall():
                tree.insert("", "end", values=row)
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"View doctor appointments error: {e}")

        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

    def _manage_records(self):
        frame = self._create_frame("Manage Medical Records")

        ttkb.Label(frame, text="Patient ID:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.record_pid = ttkb.Entry(frame)
        self.record_pid.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Diagnosis:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.record_diagnosis = ttkb.Entry(frame)
        self.record_diagnosis.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Treatment:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.record_treatment = ttkb.Entry(frame)
        self.record_treatment.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        ttkb.Button(frame, text="Save", command=self._save_record,
                    bootstyle=SUCCESS).grid(row=4, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=4, column=0, pady=10, sticky="e")

    def _save_record(self):
        pid = self.record_pid.get().strip()
        diagnosis = self.record_diagnosis.get().strip()
        treatment = self.record_treatment.get().strip()

        if not all([pid, diagnosis, treatment]):
            messagebox.showerror("Error", "All fields required")
            return

        try:
            self.db.cursor.execute(
                "INSERT INTO MedicalRecords (PatientID, Diagnosis, Treatment, RecordDate) VALUES (?, ?, ?, ?)",
                (pid, diagnosis, treatment, datetime.now())
            )
            self.db.commit()
            messagebox.showinfo("Success", "Record saved")
            self._show_dashboard()
            logging.info(f"Record saved for patient {pid}")
        except Exception as e:
            messagebox.showerror("Error", f"Database error: {e}")
            logging.error(f"Save record error: {e}")

    def _update_patient_records(self):
        frame = self._create_frame("Update Patient Records")

        ttkb.Label(frame, text="Patient ID:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.record_pid = ttkb.Entry(frame)
        self.record_pid.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Diagnosis:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.record_diagnosis = ttkb.Entry(frame)
        self.record_diagnosis.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        ttkb.Label(frame, text="Treatment:").grid(row=3, column=0, padx=10, pady=10, sticky="e")
        self.record_treatment = ttkb.Entry(frame)
        self.record_treatment.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        ttkb.Button(frame, text="Update", command=self._save_record,
                    bootstyle=SUCCESS).grid(row=4, column=1, pady=10, sticky="w")
        ttkb.Button(frame, text="Back", command=self._show_dashboard,
                    bootstyle=DANGER).grid(row=4, column=0, pady=10, sticky="e")


if __name__ == "__main__":
    root = ttkb.Window(themename="cosmo")
    app = HospitalApp(root)
    try:
        root.mainloop()
    finally:
        app.db.close()