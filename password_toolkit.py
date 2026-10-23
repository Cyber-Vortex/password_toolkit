
import secrets
import string

def generate_password(length=16):
    if length < 8:
        raise ValueError("Password length must be at least 8.")

    chars = (
        string.ascii_letters
        + string.digits
        + "!@#$%^&*()-_=+"
    )

    # Ensure at least one of each character type
    password_chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+")
    ]

    password_chars += [
        secrets.choice(chars)
        for _ in range(length - len(password_chars))
    ]

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def check_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    return "Strong"


def main():
    print("\n=== SECURE PASSWORD TOOLKIT ===")
    print("1. Generate password")
    print("2. Check password strength")

    choice = input("Choose option (1/2): ").strip()

    if choice == "1":
        try:
            length = int(input("Password length (8-64): "))

            if not 8 <= length <= 64:
                print("Choose a length between 8 and 64.")
                return

            password = generate_password(length)
            print("\nGenerated password:", password)
            print("Strength:", check_strength(password))
            print("Store it securely; don't share it with others.")

        except ValueError:
            print("Please enter a valid number.")

    elif choice == "2":
        password = input("Enter a password to check: ")
        print("Estimated strength:", check_strength(password))
        print("This is a basic estimate, not a security audit.")

    else:
        print("Invalid option. Choose 1 or 2.")


if __name__ == "__main__":
    main()
