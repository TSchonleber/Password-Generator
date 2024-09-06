
import random
import string
from datetime import datetime, timedelta
from encryption_module import encrypt_data

# Function to automatically regenerate passwords if they have expired
def auto_regenerate_expired_passwords():
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
                encrypted_new_password = encrypt_data(new_password.encode()).decode()
                new_creation_date = datetime.now().strftime("%Y-%m-%d")
                
                # Update the lines with the new password and creation date
                updated_lines.append(f"Service: {service_name}
")
                updated_lines.append(f"Encrypted password: {encrypted_new_password}
")
                updated_lines.append(f"Creation date: {new_creation_date}

")
                
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
