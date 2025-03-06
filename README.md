# Hospital Management System

A Python-based desktop application for managing hospital operations, including user authentication, patient management, appointment scheduling, and medical record management. Built using `tkinter`, `ttkbootstrap`, and `pyodbc` for SQL Server integration.

## Features
- **User Authentication**: Login, signup, and password reset with email token generation.
- **Role-Based Access**:
  - **Admin**: Manage patients, doctors, appointments, and records.
  - **Doctor**: View patients, appointments, and update records.
  - **Receptionist**: Manage patients and appointments.
- **UI Customization**: Theme selection and font size adjustment.
- **Database Integration**: SQL Server for data storage (schema included in repo).
- **Email Notifications**: Password reset tokens sent via SMTP (Gmail).
- **Logging**: Activity logging to `app.log`.

## Prerequisites
To run this application, ensure you have:
1. **Python 3.8+**: [Download Python](https://www.python.org/downloads/)
2. **SQL Server**: Installed locally or accessible (e.g., via SSMS).
3. **Required Python Libraries**:
   ```bash
   pip install ttkbootstrap pyodbc bcrypt
   ```
4. **Gmail Account**: For sending password reset emails (app-specific password required if 2FA is enabled).

## Setup Instructions

### 1. Clone the Repository
Clone this repository to your local machine:
```bash
git clone https://github.com/dogahwisdom/healthcareUI
cd healthcareUI
```

### 2. Database Configuration
The database schema is provided in the repository as `schema.sql`. Follow these steps to set it up:

#### a. Create the Database
1. Open **SQL Server Management Studio (SSMS)**.
2. Connect to your SQL Server instance (e.g., `localhost` or `SERVERNAME\INSTANCE`).
3. Open the `schema.sql` file from the repository.
4. Execute the script to create the `HospitalManagement` database and its tables:
   - `Users`
   - `Patients`
   - `Doctors`
   - `Appointments`
   - `MedicalRecords`
   - `PasswordResetTokens`

#### b. Update Database Connection
In `hospital_app.py`, modify the `Database` class connection string to match your SQL Server setup:
```python
self.conn = pyodbc.connect(
    "DRIVER={SQL Server};"
    "SERVER=ACTIVEPROGRAMME;"  # Replace with your server name (e.g., localhost, DESKTOP-XXXXX\SQLEXPRESS)
    "DATABASE=HospitalManagement;"
    "Trusted_Connection=yes"   # Use Windows Authentication; for SQL auth, use UID=your_username;PWD=your_password
)
```
- **Server Name**: Find this in SSMS under "Server name".
- **Authentication**: If using SQL Server authentication, replace `Trusted_Connection=yes` with `UID=your_username;PWD=your_password`.

### 3. Email Configuration
Update the `EMAIL_CONFIG` dictionary in `hospital_app.py` with your Gmail credentials:
```python
EMAIL_CONFIG = {
    "HOST": "smtp.gmail.com",
    "PORT": 587,
    "USER": "your_email@gmail.com",          # Your Gmail address
    "PASSWORD": "your_email_password"        # Your Gmail password or app-specific password
}
```
- **App-Specific Password**: If 2FA is enabled, generate an [App Password](https://myaccount.google.com/apppasswords) and use it instead.

### 4. Install Dependencies
Install the required Python libraries:
```bash
pip install ttkbootstrap pyodbc bcrypt
```
- Ensure the ODBC Driver for SQL Server is installed (`pyodbc.drivers()` to check available drivers).

### 5. Run the Application
1. Ensure you're in the repository directory.
2. Run the script:
   ```bash
   python hospital_app.py
   ```
3. The application window will open with the login screen.

## Usage
- **Signup**: Create a new user with a role (Admin, Doctor, Receptionist).
- **Login**: Use credentials to access your role-specific dashboard.
- **Forgot Password**: Reset your password via email token.
- **Dashboard**: Perform tasks like adding patients, scheduling appointments, or managing records.

## Troubleshooting
- **Database Connection Error**:
  - Verify the server name and database name in the connection string.
  - Ensure SQL Server is running and accessible.
  - Install the ODBC Driver if missing ([Microsoft ODBC Driver](https://docs.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)).
- **Email Sending Error**:
  - Check `EMAIL_CONFIG` credentials.
  - Ensure Gmail allows less secure apps or use an app-specific password.
- **Module Not Found**:
  - Confirm all dependencies are installed (`pip list`).

## Logging
Activity is logged to `app.log` in the project directory. Check it for:
- Login attempts
- Errors
- User actions

## Notes
- Passwords are hashed with `bcrypt` for security.
- The UI leverages `ttkbootstrap` for modern, customizable themes.
- The default server name in the code is `ACTIVEPROGRAMME`; adjust it to your environment.

## Contributing
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit changes (`git commit -m "Add feature"`).
4. Push to your fork (`git push origin feature-name`).
5. Open a pull request.

## License
This project is unlicensed and free to use or modify as needed.

