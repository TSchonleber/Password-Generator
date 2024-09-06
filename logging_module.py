
from datetime import datetime

# Enhanced logging function for audit purposes
def log_activity(action, status):
    with open('activity_log.txt', 'a') as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] {action} - {status}\n")

# Additional logging for key rotation
def log_key_rotation():
    log_activity("KEY_ROTATION", "Encryption keys rotated successfully")

# Example logging for other activities
def log_otp_attempt(success):
    if success:
        log_activity("OTP_ATTEMPT", "OTP verification successful")
    else:
        log_activity("OTP_ATTEMPT", "OTP verification failed")
