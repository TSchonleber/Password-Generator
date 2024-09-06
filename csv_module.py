
import csv

# Function to export passwords to an encrypted CSV file
def export_passwords_to_csv():
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
    try:
        with open('passwords_import.csv', 'r') as csvfile:
            csv_reader = csv.reader(csvfile)
            next(csv_reader)  # Skip header

            with open('passwords.txt', 'a') as file:
                for row in csv_reader:
                    service_name, encrypted_password, creation_date = row

                    # Append each row to the passwords.txt file
                    file.write(f"Service: {service_name}
")
                    file.write(f"Encrypted password: {encrypted_password}
")
                    file.write(f"Creation date: {creation_date}

")

        print("Passwords successfully imported from 'passwords_import.csv'.")

    except FileNotFoundError:
        print("No CSV file found to import from.")
    except Exception as e:
        print(f"Error during import: {e}")
