
import json
from encryption_module import encrypt_data

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
    encrypted_password = encrypt_data(password.encode()).decode()

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
    encrypted_password = encrypt_data(password.encode()).decode()

    return encrypted_password in history[service_name]
