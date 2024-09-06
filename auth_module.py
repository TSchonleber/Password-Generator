
import hashlib
import getpass
import os
import smtplib
from random import randint
from email.mime.text import MIMEText
from logging_module import log_activity

# Fetch the master password from the environment variable
MASTER_PASSWORD_ENV = "MASTER_PASSWORD"
MASTER_PASSWORD = os.getenv(MASTER_PASSWORD_ENV)
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
if MASTER_PASSWORD is None:
    print(f"Error: Master password not found in environment. Please set {MASTER_PASSWORD_ENV}.")
    exit()

# Hash the master password using SHA-256
MASTER_PASSWORD_HASH = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()

# Function to generate and send OTP via email
def send_otp_via_email(receiver_email):
    otp = str(randint(100000, 999999))  # Generate 6-digit OTP
    sender_email = SENDER_EMAIL  # Replace with your email
    sender_password = SENDER_PASSWORD  # Replace with your email password
    subject = "Your OTP for Password Manager"
    body = f"Your one-time password (OTP) is: {otp}"

    msg = MIMEText(body)
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"OTP sent to {receiver_email}")
        return otp  # Return the generated OTP
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return None

# Function to verify OTP
def verify_otp(sent_otp):
    for _ in range(3):  # Allow 3 attempts to enter the correct OTP
        entered_otp = input("Enter the OTP sent to your email: ")
        if entered_otp == sent_otp:
            print("OTP verified successfully.")
            return True
        else:
            print("Incorrect OTP. Please try again.")
    print("Too many incorrect OTP attempts. Exiting.")
    return False

# Function to verify the master password and 2FA OTP
def verify_master_password():
    print("Please enter the master password to access the password manager.")
    for _ in range(3):  # Allow 3 attempts to enter the correct password
        entered_password = getpass.getpass("Master password: ")
        entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()

        if entered_password_hash == MASTER_PASSWORD_HASH:
            print("Master password verified.")
            log_activity("Master password login", "Success")

            # Prompt for email to send OTP
            receiver_email = input("Enter your email address for OTP verification: ")
            otp = send_otp_via_email(receiver_email)

            if otp is None:
                print("Error in sending OTP. Exiting.")
                return False

            # Verify the OTP sent via email
            if verify_otp(otp):
                print("Access granted.")
                log_activity("2FA OTP verified", "Success")
                return True
            else:
                log_activity("2FA OTP verification", "Failed")
                return False
        else:
            print("Incorrect master password. Please try again.")
            log_activity("Master password login", "Failed")
    print("Too many incorrect attempts. Exiting.")
    log_activity("Master password login", "Too many failed attempts")
    return False
