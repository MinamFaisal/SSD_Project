from flask import Flask, render_template, request, redirect, url_for, abort, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt  # Import bcrypt for password hashing
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Initialize CSRF protection and bcrypt
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

# Custom validation function for email
def validate_email(email):
    # Basic email regex
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Custom validation function for inputs (to prevent SQL-like injections)
def validate_input(data):
    # Disallow SQL-related characters like semicolons, quotes, etc.
    sql_keywords = ["SELECT", "INSERT", "DELETE", "UPDATE", "DROP", "--", "'"]
    for keyword in sql_keywords:
        if keyword.lower() in data.lower():
            return False
    return True

# Simulated hashed password (you would store this in your database)
# Hash the default password 'password123' using bcrypt
hashed_password = bcrypt.generate_password_hash('password123').decode('utf-8')

# Forms using Flask-WTF for CSRF protection
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])  # Remove Email() validator
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')

# 404 Error handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# 500 Error handler
@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

# Route for the login form
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Validate input (prevent SQL injection-like input)
        if not validate_input(username) or not validate_input(password):
            return abort(404)

        # Log the password before checking
        print("Password before hashing:", password)

        # Check credentials (hashed password check)
        if username == 'admin' and bcrypt.check_password_hash(hashed_password, password):
            # Log the successful password check
            print("Password check passed. Hashed password:", hashed_password)
            session['user'] = username  # Set the session to indicate the user is logged in
            return redirect(url_for('contact'))
        else:
            # Log the failed login attempt
            print("Invalid login attempt for username:", username)
            return abort(404)  # Invalid login
    
    return render_template('login.html', form=form)


# Route for the contact form
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'user' not in session:  # Check if user is logged in
        return abort(404)  # Redirect to 404 if not logged in

    form = ContactForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        message = form.message.data

        # Custom email validation using the validate_email function
        if not validate_email(email):
            return abort(404)  # Abort if email is not valid

        # Validate all other inputs
        if not validate_input(name) or not validate_input(message):
            return abort(404)

        # Simulate form submission
        return "Message sent successfully!"
    
    return render_template('contact.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
