import random
import string
import os
import time
import base64
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from encryption_module import encrypt_data, decrypt_data
from logging_module import log_activity
from history_module import add_password_to_history, is_password_in_history
from csv_module import export_passwords_to_csv, import_passwords_from_csv
from regeneration_module import auto_regenerate_expired_passwords
from auth_module import verify_master_password

MIN_PASSWORD_LENGTH = 8
EXPIRATION_DAYS = 90
SESSION_TIMEOUT = 300  # 5 minutes session timeout
last_activity_time = time.time()

# Function to update the last activity time
def update_last_activity_time():
    global last_activity_time
    last_activity_time = time.time()

# Function to check if the session has timed out
def check_session_timeout():
    if time.time() - last_activity_time > SESSION_TIMEOUT:
        print("Session timed out due to inactivity. Please log in again.")
        if not verify_master_password():
            exit()
        update_last_activity_time()

# Function to notify the user if any passwords are expired or nearing expiration
def notify_expired_passwords():
    check_session_timeout()
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
                elif (expiration_date - current_date).days <= 5:
                    near_expiration_services.append(service_name)

            if expired_services:
                print("\n--- Expired Passwords ---")
                for service in expired_services:
                    print(f"Your password for {service} has expired! Please generate a new one.")
            else:
                print("No passwords have expired.")

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

# Password Generation with history check and save
def generate_and_save_password():
    notify_expired_passwords()  # Notify user about expired passwords
    check_session_timeout()  # Check for session timeout before proceeding
    service_name = input("Enter the name of the service (e.g., email, social media): ")
    password_length = int(input("Enter the desired password length (min 8 characters): "))

    while password_length < MIN_PASSWORD_LENGTH:
        print(f"Password length must be at least {MIN_PASSWORD_LENGTH} characters.")
        password_length = int(input(f"Please enter a valid password length (min {MIN_PASSWORD_LENGTH} characters): "))

    include_lowercase = input("Include lowercase letters? (y/n): ").lower() == 'y'
    include_uppercase = input("Include uppercase letters? (y/n): ").lower() == 'y'
    include_digits = input("Include digits? (y/n): ").lower() == 'y'
    include_special = input("Include special characters? (y/n): ").lower() == 'y'

    if not (include_lowercase or include_uppercase or include_digits or include_special):
        print("At least one character type must be selected. Please try again.")
        return

    lowercase_letters = string.ascii_lowercase if include_lowercase else ''
    uppercase_letters = string.ascii_uppercase if include_uppercase else ''
    digits = string.digits if include_digits else ''
    special_characters = string.punctuation if include_special else ''

    character_pool = lowercase_letters + uppercase_letters + digits + special_characters

    valid_password = False
    while not valid_password:
        password = []
        if include_lowercase:
            password.append(random.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(random.choice(string.ascii_uppercase))
        if include_digits:
            password.append(random.choice(string.digits))
        if include_special:
            password.append(random.choice(string.punctuation))

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

    encrypted_password = encrypt_data(final_password.encode()).decode()
    creation_date = datetime.now().strftime("%Y-%m-%d")

    try:
        with open('passwords.txt', 'a') as file:
            file.write(f"Service: {service_name}\n")
            file.write(f"Encrypted password: {encrypted_password}\n")
            file.write(f"Creation date: {creation_date}\n\n")
        print(f"Password for {service_name} saved.")
        log_activity(f"Password generated for {service_name}", "Success")
    except Exception as e:
        print(f"An error occurred while saving the password: {e}")
        log_activity(f"Password generation for {service_name}", f"Failed: {e}")

    # Add the password to history
    add_password_to_history(service_name, final_password)

# Function to automatically regenerate expired passwords
auto_regenerate_expired_passwords()

# CSV Export and Import
def handle_csv_operations():
    print("1. Export passwords to CSV")
    print("2. Import passwords from CSV")
    choice = input("Enter your choice: ")
    if choice == '1':
        export_passwords_to_csv()
    elif choice == '2':
        import_passwords_from_csv()
    else:
        print("Invalid choice")

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

        encrypted_data = encrypt_data(password_data.encode(), encryption_key)
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
