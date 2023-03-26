import secrets
def generate_otp():
    secrets_generator = secrets.SystemRandom()
    return secrets_generator.randint(100000,999999)