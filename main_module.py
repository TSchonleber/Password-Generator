
from encryption_module import rotate_encryption_key, encrypt_data, decrypt_data
from logging_module import log_activity, log_key_rotation
from auth_module import verify_master_password
from password_manager import generate_new_password, save_password, retrieve_password, notify_expired_passwords, backup_passwords_to_file, restore_passwords_from_backup
import schedule
import time

# Function to get current encrypted data
def get_encrypted_data():
    # Assuming encrypted passwords are stored in 'passwords_encrypted.txt'
    with open('passwords_encrypted.txt', 'r') as file:
        return file.read()

# Schedule automatic key rotation every 30 days
def schedule_key_rotation():
    current_encrypted_data = get_encrypted_data()
    rotate_encryption_key(current_encrypted_data)  # Rotate the encryption key
    log_key_rotation()  # Log the key rotation event
    print("Automatic key rotation completed.")

# Main function to run the password manager
def run_password_manager():
    log_activity("Password Manager", "Session started")

    # Schedule key rotation to occur every 30 days
    schedule.every(30).days.do(schedule_key_rotation)

    if not verify_master_password():
        log_activity("Password Manager", "Authentication failed. Exiting.")
        return

    notify_expired_passwords()  # Notify user about expired passwords

    while True:
        print("\n--- Password Manager ---")
        print("1. Generate a new password")
        print("2. Retrieve a password")
        print("3. Backup passwords")
        print("4. Restore passwords from backup")
        print("5. Rotate Encryption Key")  # Option for manual key rotation
        print("6. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            service_name = input("Enter the service name: ")
            password = generate_new_password()
            save_password(service_name, password)
            log_activity("Password Manager", f"Password generated for {service_name}")
        elif choice == '2':
            service_name = input("Enter the service name to retrieve: ")
            retrieve_password(service_name)
            log_activity("Password Manager", f"Password retrieved for {service_name}")
        elif choice == '3':
            backup_passwords_to_file()
            log_activity("Password Manager", "Passwords backed up successfully")
        elif choice == '4':
            restore_passwords_from_backup()
            log_activity("Password Manager", "Passwords restored from backup")
        elif choice == '5':  # Manual key rotation
            current_encrypted_data = get_encrypted_data()  # Retrieve current data
            rotate_encryption_key(current_encrypted_data)  # Rotate key manually
            log_key_rotation()  # Log the key rotation
            print("Encryption key rotated successfully.")
        elif choice == '6':
            log_activity("Password Manager", "Session ended")
            print("Exiting Password Manager.")
            break
        else:
            print("Invalid choice. Please try again.")

        # Run scheduled tasks in the background
        schedule.run_pending()
        time.sleep(1)  # Small sleep to prevent tight loops

if __name__ == "__main__":
    run_password_manager()
