from app import app, hashed_password  # Import the app and the hashed password
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt(app)

def test_password_hashing():
    # Test the correct password
    correct_password = 'password123'
    assert bcrypt.check_password_hash(hashed_password, correct_password) == True, "Password should match"

    # Test the incorrect password
    incorrect_password = 'wrongpassword'
    assert bcrypt.check_password_hash(hashed_password, incorrect_password) == False, "Password should not match"

if __name__ == "__main__":
    test_password_hashing()
    print("All tests passed!")
