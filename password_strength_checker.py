import re

def assess_password_strength(password):
    """
    Assess the strength of a password based on predefined criteria.
    """
    feedback = []

    # Criteria for password strength
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[^A-Za-z0-9]', password))

    # Evaluate criteria
    if not length_criteria:
        feedback.append("Password should be at least 8 characters long.")
    if not uppercase_criteria:
        feedback.append("Password should contain at least one uppercase letter.")
    if not lowercase_criteria:
        feedback.append("Password should contain at least one lowercase letter.")
    if not number_criteria:
        feedback.append("Password should contain at least one number.")
    if not special_char_criteria:
        feedback.append("Password should contain at least one special character.")

    # Return feedback and whether the password is valid
    if not feedback:
        return True, "Password meets all criteria!"
    else:
        return False, feedback

def main():
    """
    Main function to run the password strength checker.
    """
    print("Password Strength Assessment Tool")
    print("---------------------------------")
    print("Your password must meet the following criteria:")
    print("- At least 8 characters long")
    print("- Contains at least one uppercase letter")
    print("- Contains at least one lowercase letter")
    print("- Contains at least one number")
    print("- Contains at least one special character")
    print("---------------------------------")

    while True:
        password = input("Enter your password: ")
        is_valid, feedback = assess_password_strength(password)

        if is_valid:
            print("\nPassword Strength: Strong")
            print(feedback)
            break
        else:
            print("\nPassword Strength: Weak")
            print("Feedback to improve your password:")
            for message in feedback:
                print(f"- {message}")
            print("Please try again.\n")

if __name__ == "__main__":
    main()