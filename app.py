
import string
import random
import hashlib  # For hashing the master password
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import getpass  # For securely entering the master password without displaying it
import os  # For checking file existence
import time  # For implementing the session timeout
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from random import randint
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

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

# Function to notify the user if any passwords are expired or nearing expiration
def notify_expired_passwords():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
            expired_services = []
            near_expiration_services = []
            current_date = datetime.now()

            for i in range(0, len(lines), 4):  # Reading 4 lines at a time (service, password, creation date, blank)
                service_name = lines[i].strip().split(": ")[1]
                creation_date = datetime.strptime(lines[i + 2].strip().split(": ")[1], "%Y-%m-%d")
                expiration_date = creation_date + timedelta(days=EXPIRATION_DAYS)
                
                if current_date > expiration_date:
                    expired_services.append(service_name)
                elif (expiration_date - current_date).days <= 5:  # Password expires in less than or equal to 5 days
                    near_expiration_services.append(service_name)

            # Notify about expired passwords
            if expired_services:
                print("\n--- Expired Passwords ---")
                for service in expired_services:
                    print(f"Your password for {service} has expired! Please generate a new one.")
            else:
                print("No passwords have expired.")

            # Notify about passwords nearing expiration
            if near_expiration_services:
                print("\n--- Passwords Nearing Expiration ---")
                for service in near_expiration_services:
                    print(f"Your password for {service} will expire in less than 5 days. Please consider updating it.")

    except FileNotFoundError:
        print("No passwords stored yet.")

# Function to enforce strong password creation
def enforce_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.islower() for char in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(char.isupper() for char in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must contain at least one digit."
    if not any(char in string.punctuation for char in password):
        return False, "Password must contain at least one special character."
    
    return True, "Password is strong."

# Update in generate_and_save_password function to enforce strength
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

        # Enforce password strength rules
        is_strong, message = enforce_password_strength(final_password)
        if not is_strong:
            print(message)
            print("Regenerating a stronger password...")
        else:
            valid_password = True
            print(f"Password Strength: {message}")

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

# Function to securely encrypt the password data for backup
def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()
    return encryptor.tag + ciphertext

# Function to decrypt the encrypted password data for restoration
def decrypt_data(ciphertext, key):
    tag, ciphertext = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12), tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Backup function: Encrypt the password file and save it as a backup
def backup_passwords_to_file():
    check_session_timeout()  # Check for session timeout before proceeding
    encryption_key = os.getenv('BACKUP_ENCRYPTION_KEY')  # Backup key from env variable
    if encryption_key is None:
        print("Error: Backup encryption key is not set in the environment variables.")
        return
    encryption_key = base64.urlsafe_b64decode(encryption_key)
    try:
        with open('passwords.txt', 'r') as file:
            password_data = file.read()

        encrypted_data = encrypt_data(password_data, encryption_key)
        with open('passwords_backup.enc', 'wb') as backup_file:
            backup_file.write(encrypted_data)
        print("Passwords successfully backed up and encrypted.")
    except FileNotFoundError:
        print("No passwords found to back up.")

# Restore function: Decrypt the backup file and restore the passwords
def restore_passwords_from_backup():
    check_session_timeout()  # Check for session timeout before proceeding
    encryption_key = os.getenv('BACKUP_ENCRYPTION_KEY')  # Backup key from env variable
    if encryption_key is None:
        print("Error: Backup encryption key is not set in the environment variables.")
        return
    encryption_key = base64.urlsafe_b64decode(encryption_key)
    try:
        with open('passwords_backup.enc', 'rb') as backup_file:
            encrypted_data = backup_file.read()

        decrypted_data = decrypt_data(encrypted_data, encryption_key)
        with open('passwords.txt', 'w') as restore_file:
            restore_file.write(decrypted_data.decode())
        print("Passwords successfully restored from the encrypted backup.")
    except FileNotFoundError:
        print("No backup file found.")
    except Exception as e:
        print(f"Error during restoration: {e}")

import json

# Function to load password history from a file
def load_password_history():
    try:
        with open('password_history.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# Function to save password history to a file
def save_password_history(history):
    with open('password_history.json', 'w') as file:
        json.dump(history, file)

# Function to add a password to the history
def add_password_to_history(service_name, password):
    history = load_password_history()
    
    # Encrypt the password before storing it in the history
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    # Add the password to the history for the specific service
    if service_name not in history:
        history[service_name] = []
    history[service_name].append(encrypted_password)

    # Limit the history size to the last 5 passwords per service (optional)
    if len(history[service_name]) > 5:
        history[service_name] = history[service_name][-5:]

    save_password_history(history)

# Function to check if a password was previously used for a service
def is_password_in_history(service_name, password):
    history = load_password_history()

    if service_name not in history:
        return False

    # Encrypt the password to check against stored history
    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    return encrypted_password in history[service_name]

# Update in generate_and_save_password function to check history
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

        # Enforce password strength rules
        is_strong, message = enforce_password_strength(final_password)
        if not is_strong:
            print(message)
            print("Regenerating a stronger password...")
            continue

        # Check if the password was previously used
        if is_password_in_history(service_name, final_password):
            print(f"This password has been used before for {service_name}. Generating a new password...")
            continue

        valid_password = True
        print(f"Password Strength: {message}")

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

    # Add the password to history
    add_password_to_history(service_name, final_password)

import csv

# Function to export passwords to an encrypted CSV file
def export_passwords_to_csv():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        
        with open('passwords_export.csv', 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['Service Name', 'Encrypted Password', 'Creation Date'])  # Header

            for i in range(0, len(lines), 4):  # Reading 4 lines at a time (service, password, creation date, blank)
                service_name = lines[i].strip().split(": ")[1]
                encrypted_password = lines[i + 1].strip().split(": ")[1]
                creation_date = lines[i + 2].strip().split(": ")[1]

                csv_writer.writerow([service_name, encrypted_password, creation_date])

        print("Passwords successfully exported to 'passwords_export.csv'.")

    except FileNotFoundError:
        print("No passwords found to export.")

# Function to import passwords from an encrypted CSV file
def import_passwords_from_csv():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        with open('passwords_import.csv', 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            next(csv_reader)  # Skip header

            with open('passwords.txt', 'a') as file:
                for row in csv_reader:
                    service_name, encrypted_password, creation_date = row

                    # Append each row to the passwords.txt file
                    file.write(f"Service: {service_name}\n")
                    file.write(f"Encrypted password: {encrypted_password}\n")
                    file.write(f"Creation date: {creation_date}\n\n")

        print("Passwords successfully imported from 'passwords_import.csv'.")

    except FileNotFoundError:
        print("No CSV file found to import from.")
    except Exception as e:
        print(f"Error during import: {e}")

# Function to automatically regenerate passwords if they have expired
def auto_regenerate_expired_passwords():
    check_session_timeout()  # Check for session timeout before proceeding
    try:
        with open('passwords.txt', 'r') as file:
            lines = file.readlines()
        
        updated_lines = []
        current_date = datetime.now()

        for i in range(0, len(lines), 4):  # Reading 4 lines at a time (service, password, creation date, blank)
            service_name = lines[i].strip().split(": ")[1]
            encrypted_password = lines[i + 1].strip().split(": ")[1]
            creation_date = datetime.strptime(lines[i + 2].strip().split(": ")[1], "%Y-%m-%d")
            expiration_date = creation_date + timedelta(days=EXPIRATION_DAYS)

            # Check if password is expired
            if current_date > expiration_date:
                # Regenerate a new password if expired
                print(f"Password for {service_name} has expired. Generating a new one...")
                new_password = generate_new_password()
                
                # Encrypt the new password and update the expiration date
                encrypted_new_password = cipher_suite.encrypt(new_password.encode()).decode()
                new_creation_date = datetime.now().strftime("%Y-%m-%d")
                
                # Update the lines with the new password and creation date
                updated_lines.append(f"Service: {service_name}\n")
                updated_lines.append(f"Encrypted password: {encrypted_new_password}\n")
                updated_lines.append(f"Creation date: {new_creation_date}\n\n")
                
                # Notify user
                print(f"New password for {service_name} has been generated and saved.")
            else:
                # Keep the original password if not expired
                updated_lines.extend(lines[i:i + 4])

        # Save the updated passwords back to the file
        with open('passwords.txt', 'w') as file:
            file.writelines(updated_lines)

    except FileNotFoundError:
        print("No passwords found to check for expiration.")
    except Exception as e:
        print(f"Error during auto-regeneration: {e}")

# Helper function to generate a new password
def generate_new_password():
    password_length = 12  # Default password length

    # Character sets for generating the password
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation

    character_pool = lowercase_letters + uppercase_letters + digits + special_characters

    password = []
    password.append(random.choice(lowercase_letters))  # Ensure at least one lowercase letter
    password.append(random.choice(uppercase_letters))  # Ensure at least one uppercase letter
    password.append(random.choice(digits))  # Ensure at least one digit
    password.append(random.choice(special_characters))  # Ensure at least one special character

    # Fill the remaining length with random characters
    remaining_length = password_length - len(password)
    password += random.choices(character_pool, k=remaining_length)

    # Shuffle the password to randomize it
    random.shuffle(password)
    
    return ''.join(password)
