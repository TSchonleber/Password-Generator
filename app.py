
import string
import random
import hashlib  # For hashing the master password
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import getpass  # For securely entering the master password without displaying it
import os  # For checking file existence
import time  # For implementing the session timeout
from dotenv import load_dotenv

load_dotenv()

# Generate an encryption key for encrypting the password
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

# Minimum password length enforcement
MIN_PASSWORD_LENGTH = 8
EXPIRATION_DAYS = 90  # Password expires after 90 days
SESSION_TIMEOUT = 300  # Session timeout in seconds (5 minutes)

# Hash the master password using SHA-256

import os

# Remove the hardcoded master password and retrieve it from an environment variable
MASTER_PASSWORD_ENV = "MASTER_PASSWORD"  # Name of the environment variable
MASTER_PASSWORD = os.getenv(MASTER_PASSWORD_ENV)

if MASTER_PASSWORD is None:
    print(f"Error: Master password not found in environment. Please set {MASTER_PASSWORD_ENV}.")
    exit()

# Hash the master password using SHA-256
MASTER_PASSWORD_HASH = hashlib.sha256(MASTER_PASSWORD.encode()).hexdigest()


# Track the last activity time
last_activity_time = time.time()

# Function to verify the master password by comparing the hash
def verify_master_password():
    print("Please enter the master password to access the password manager.")
    for _ in range(3):  # Allow 3 attempts to enter the correct password
        entered_password = getpass.getpass("Master password: ")  # Use getpass for secure input
        entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()  # Hash the entered password

        if entered_password_hash == MASTER_PASSWORD_HASH:
            print("Access granted.")
            return True
        else:
            print("Incorrect master password. Please try again.")
    print("Too many incorrect attempts. Exiting.")
    return False

# Function to update the last activity time
def update_last_activity_time():
    global last_activity_time
    last_activity_time = time.time()

# Function to check if the session has timed out
def check_session_timeout():
    if time.time() - last_activity_time > SESSION_TIMEOUT:
        print("Session timed out due to inactivity. Please log in again.")
        if not verify_master_password():
            exit()  # Exit the program if the master password is incorrect after timeout
        update_last_activity_time()  # Reset the last activity time after re-authentication

# Function to validate the password complexity
def validate_password_complexity(password):
    has_lowercase = any(char.islower() for char in password)
    has_uppercase = any(char.isupper() for char in password)
    has_digits = any(char.isdigit() for char in password)
    has_special = any(char in string.punctuation for char in password)

    return has_lowercase and has_uppercase and has_digits and has_special

# Function to prevent consecutive identical characters
def add_non_repeating_char(char_pool, password):
    char = random.choice(char_pool)
    while password and char == password[-1]:  # Prevent consecutive identical characters
        char = random.choice(char_pool)
    return char

# Function to check if the password has expired
def check_password_expiration(creation_date_str):
    creation_date = datetime.strptime(creation_date_str, "%Y-%m-%d")
    current_date = datetime.now()
    expiration_date = creation_date + timedelta(days=EXPIRATION_DAYS)
    return current_date > expiration_date

# Function to notify the user if any passwords have expired
def notify_expired_passwords():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
            expired_services = []
            for i in range(0, len(lines), 4):  # Reading 4 lines at a time (service, password, creation date, blank)
                service_name = lines[i].strip().split(": ")[1]
                creation_date = lines[i + 2].strip().split(": ")[1]
                if check_password_expiration(creation_date):
                    expired_services.append(service_name)

            if expired_services:
                print("\n--- Expired Passwords ---")
                for service in expired_services:
                    print(f"Your password for {service} has expired! Please generate a new one.")
            else:
                print("No passwords have expired.")
    except FileNotFoundError:
        print("No passwords stored yet.")

# Password Manager Main Functionality
def password_manager():
    if not verify_master_password():
        return  # Exit if the master password is incorrect

    # Automatically check for expired passwords when the manager starts
    notify_expired_passwords()
    update_last_activity_time()

    while True:
        check_session_timeout()  # Check if the session has timed out before any operation
        print("\n--- Password Manager ---")
        print("1. Generate and save a new password")
        print("2. Retrieve a password")
        print("3. Backup passwords")
        print("4. Restore passwords from backup")
        print("5. Search for a password by service")
        print("6. List all passwords sorted by creation date")
        print("7. Exit")
        choice = input("Enter your choice: ")
        update_last_activity_time()  # Reset the session timer after every action

        if choice == '1':
            generate_and_save_password()
        elif choice == '2':
            retrieve_password()
        elif choice == '3':
            backup_passwords()
        elif choice == '4':
            restore_passwords()
        elif choice == '5':
            search_password_by_service()
        elif choice == '6':
            list_passwords_sorted_by_date()
        elif choice == '7':
            print("Exiting Password Manager.")
            break
        else:
            print("Invalid choice. Please try again.")

# Function to generate a new password and save it with a service name
def generate_and_save_password():
    check_session_timeout()  # Check for session timeout before proceeding
    service_name = input("Enter the name of the service (e.g., email, social media): ")
    password_length = int(input("Enter the desired password length (min 8 characters): "))

    # Ensure the password length is at least the minimum
    while password_length < MIN_PASSWORD_LENGTH:
        print(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters.")
        password_length = int(input(f"Please enter a valid password length (min {MIN_PASSWORD_LENGTH} characters): "))

    # Character Preferences
    include_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
    include_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
    include_digits = input("Include digits? (y/n): ").lower() == 'y'
    include_special = input("Include special characters? (y/n): ").lower() == 'y'

    # Validate one character type is selected
    if not (include_lowercase or include_uppercase or include_digits or include_special):
        print("At least one character type must be selected. Please try again.")
        return

    # Define character sets
    lowercase_letters = string.ascii_lowercase if include_lowercase else ''
    uppercase_letters = string.ascii_uppercase if include_uppercase else ''
    digits = string.digits if include_digits else ''
    special_characters = string.punctuation if include_special else ''

    # Build character pool based on user preferences
    character_pool = lowercase_letters + uppercase_letters + digits + special_characters

    # Generate a valid password based on complexity rules
    valid_password = False
    while not valid_password:
        password = []
        if include_lowercase:
            password.append(random.choice(string.ascii_lowercase))  # Add one lowercase letter
        if include_uppercase:
            password.append(random.choice(string.ascii_uppercase))  # Add one uppercase letter
        if include_digits:
            password.append(random.choice(string.digits))  # Add one digit
        if include_special:
            password.append(random.choice(string.punctuation))  # Add one special character

        remaining_length = password_length - len(password)
        if remaining_length > 0:
            password += random.choices(character_pool, k=remaining_length)

        random.shuffle(password)
        final_password = ''.join(password)

        # Validate that the password meets complexity requirements
        valid_password = validate_password_complexity(final_password)

        if not valid_password:
            print("Password does not meet complexity requirements. Regenerating...")

    # Display password strength
    strength = password_strength(final_password)
    print(f"Password Strength: {strength}")

    # Save the password and creation date
    encrypted_password = cipher_suite.encrypt(final_password.encode())
    creation_date = datetime.now().strftime("%Y-%m-%d")

    # Save the service name, encrypted password, and creation date to a file
    try:
        with open('passwords.txt', 'a') as file:
            file.write(f"Service: {service_name}\n")
            file.write(f"Encrypted password: {encrypted_password.decode()}\n")
            file.write(f"Creation date: {creation_date}\n\n")
        print(f"Password for {service_name} saved.")
    except Exception as e:
        print(f"An error occurred while saving the password: {e}")

# Function to retrieve a stored password
def retrieve_password():
    check_session_timeout()  # Check for session timeout before proceeding
    service_name = input("Enter the name of the service to retrieve the password: ")

    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
            found_service = False
            encrypted_password = None
            creation_date = None
            for i in range(0, len(lines), 4):  # Reading 4 lines at a time (service, password, creation date, blank)
                if lines[i].strip().split(": ")[1] == service_name:
                    found_service = True
                    encrypted_password = lines[i + 1].strip().split(": ")[1]
                    creation_date = lines[i + 2].strip().split(": ")[1]
                    break

            if found_service:
                # Decrypt the password
                decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()

                # Check for password expiration
                if check_password_expiration(creation_date):
                    print(f"Your password for {service_name} has expired! Please generate a new one.")
                else:
                    print(f"Your password for {service_name} is: {decrypted_password}")
                    # Display password strength when retrieved
                    strength = password_strength(decrypted_password)
                    print(f"Password Strength: {strength}")
            else:
                print(f"No password found for the service {service_name}.")

    except FileNotFoundError:
        print("No passwords stored yet.")

# Function to backup passwords to a backup file
def backup_passwords():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        if os.path.exists('passwords.txt'):
            backup_file = 'passwords_backup.txt'
            os.system(f'cp passwords.txt {backup_file}')
            print(f"Backup created successfully at {backup_file}")
        else:
            print("No passwords to backup.")
    except Exception as e:
        print(f"An error occurred during backup: {e}")

# Function to restore passwords from a backup file
def restore_passwords():
    check_session_timeout()  # Check for session timeout before proceeding
    backup_file = 'passwords_backup.txt'
    if os.path.exists(backup_file):
        try:
            os.system(f'cp {backup_file} passwords.txt')
            print(f"Passwords restored from {backup_file}")
        except Exception as e:
            print(f"An error occurred during restore: {e}")
    else:
        print("No backup file found.")

# Function to search for a password by service
def search_password_by_service():
    check_session_timeout()
    search_term = input("Enter the service name to search for: ").lower()
    found = False
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines), 4):
                service = lines[i].strip().split(": ")[1].lower()
                if search_term in service:
                    print(f"Found: {lines[i].strip()}")
                    found = True
        if not found:
            print("No matching services found.")
    except FileNotFoundError:
        print("No passwords stored yet.")

# Function to list all passwords sorted by creation date
def list_passwords_sorted_by_date():
    check_session_timeout()
    passwords = []
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
            for i in range(0, len(lines), 4):
                service = lines[i].strip().split(": ")[1]
                date = lines[i + 2].strip().split(": ")[1]
                passwords.append((service, date))
        
        sorted_passwords = sorted(passwords, key=lambda x: x[1], reverse=True)
        print("\nPasswords sorted by creation date (newest first):")
        for service, date in sorted_passwords:
            print(f"{service}: Created on {date}")
    except FileNotFoundError:
        print("No passwords stored yet.")

# Run the Password Manager
password_manager()

# Function to determine password strength
def password_strength(password):
    score = 0

    # Length-based scoring
    if len(password) < 8:
        return "Very Weak"
    elif 8 <= len(password) < 12:
        score += 1
    else:
        score += 2

    # Check for character variety
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1

    # Assign strength categories
    if score <= 2:
        return "Weak"
    elif score == 3:
        return "Moderate"
    elif score == 4:
        return "Strong"
    else:
        return "Very Strong"

import smtplib
from email.mime.text import MIMEText
from random import randint

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
# Function to send an email with the OTP
def send_otp_via_email(receiver_email):
    # Generate a 6-digit OTP
    otp = str(randint(100000, 999999))

    # Email configuration
    sender_email = SENDER_EMAIL  # Replace with your Gmail address
    sender_password = SENDER_PASSWORD  # Replace with your Gmail app password
    subject = "Your OTP for Password Manager"
    body = f"Your one-time password (OTP) is: {otp}"

    # Set up the email content
    msg = MIMEText(body)
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    # Send the email using Gmail's SMTP server
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"OTP has been sent to {receiver_email}")
        return otp  # Return the OTP for verification
    except Exception as e:
        print(f"Failed to send OTP: {e}")
        return None

# Function to verify the OTP
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
        entered_password = getpass.getpass("Master password: ")  # Use getpass for secure input
        entered_password_hash = hashlib.sha256(entered_password.encode()).hexdigest()  # Hash the entered password

        if entered_password_hash == MASTER_PASSWORD_HASH:
            print("Master password verified.")

            # Prompt for email to send OTP
            receiver_email = input("Enter your email address to receive OTP: ")
            otp = send_otp_via_email(receiver_email)

            if otp is None:
                print("Error in sending OTP. Exiting.")
                return False

            # Verify the OTP sent via email
            if verify_otp(otp):
                print("Access granted.")
                return True
            else:
                return False
        else:
            print("Incorrect master password. Please try again.")
    print("Too many incorrect attempts. Exiting.")
    return False
