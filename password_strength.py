import re
import math

# List of common passwords (you can extend this list)
common_passwords = ['password', '123456', 'qwerty', 'abc123', 'admin', 'letmein', 'welcome']

# Function to analyze password complexity
def complexity_analysis(password):
    has_upper = bool(re.search(r'[A-Z]', password))
    has_lower = bool(re.search(r'[a-z]', password))
    has_number = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[\W_]', password))
    
    complexity = {
        'Uppercase Letters': has_upper,
        'Lowercase Letters': has_lower,
        'Numbers': has_number,
        'Special Characters': has_special,
    }
    return complexity

# Function to check common passwords
def is_common_password(password):
    return password.lower() in common_passwords

# Function to check for repeated patterns
def check_repeated_patterns(password):
    return bool(re.search(r'(.)\1{2,}', password))

# Function to calculate entropy
def calculate_entropy(password):
    pool_size = 0
    if re.search(r'[A-Z]', password):
        pool_size += 26  # Uppercase letters
    if re.search(r'[a-z]', password):
        pool_size += 26  # Lowercase letters
    if re.search(r'\d', password):
        pool_size += 10  # Digits
    if re.search(r'[\W_]', password):
        pool_size += 32  # Special characters
    
    if pool_size == 0:
        return 0  # If no complexity, entropy is 0
    entropy = len(password) * math.log2(pool_size)
    return entropy

# Main function to check password strength
def check_password_strength(password):
    # Basic length criteria
    length_criteria = len(password) >= 8
    complexity = complexity_analysis(password)
    common_check = is_common_password(password)
    repeated_check = check_repeated_patterns(password)
    entropy_value = calculate_entropy(password)

    # Strength assessment score
    score = 0
    if length_criteria:
        score += 1
    if all(complexity.values()):
        score += 2
    if not common_check:
        score += 1
    if not repeated_check:
        score += 1

    # Feedback message based on score
    if score == 5:
        return f"Very Strong Password! Entropy: {entropy_value:.2f} bits."
    elif score >= 3:
        return f"Moderate Password. Entropy: {entropy_value:.2f} bits."
    else:
        return "Weak Password. Improve length, complexity, and avoid common patterns."

# Function to provide detailed feedback
def detailed_feedback(password):
    feedback = ""
    complexity = complexity_analysis(password)
    
    if len(password) < 8:
        feedback += "- Password should be at least 8 characters long.\n"
    
    for criteria, met in complexity.items():
        if not met:
            feedback += f"- Password should contain {criteria}.\n"
    
    if is_common_password(password):
        feedback += "- Your password is too common. Choose a unique password.\n"
    
    if check_repeated_patterns(password):
        feedback += "- Avoid repeating characters or patterns in your password.\n"
    
    return feedback if feedback else "Great! Your password meets all complexity criteria."

# Example usage
if __name__ == "__main__":
    try:
        password = input("Enter your password: ")
        
        # Check password strength and provide detailed feedback
        print("\nPassword Strength Analysis:")
        print(check_password_strength(password))
        print("\nDetailed Feedback:")
        print(detailed_feedback(password))
        
        # Pause to keep the window open
        input("\nPress Enter to exit.")
    except Exception as e:
        print(f"An error occurred: {e}")
        input("Press Enter to close.")
