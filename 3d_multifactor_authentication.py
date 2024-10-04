from flask import Flask, redirect, request, url_for, flash, get_flashed_messages
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import pyotp

app = Flask(__name__)
app.secret_key = 'your_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)

# Mock database for users
users = {}

def get_flashed_messages_html():
    messages = get_flashed_messages()
    if messages:
        return ''.join(f"<p>{message}</p>" for message in messages)
    return ''

class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.otp_verified = False

@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    flashed_messages = get_flashed_messages_html()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            flash('Username already exists. Please choose another one.')
        else:
            # Store the user's credentials and generate an OTP secret
            otp_secret = pyotp.random_base32()  # Generate OTP secret for this user
            users[username] = {'password': password, 'otp_secret': otp_secret, 'otp_verified': False}
            flash('Signup successful! Please log in.')
            return redirect(url_for('login'))

    return f""" 
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Signup</title>
                </head>
                <body>
                    <h2>Signup</h2>
                    {flashed_messages}  <!-- Display flashed messages here -->
                    <form action="{url_for('signup')}" method="POST">
                        <label>Username:</label>
                        <input type="text" name="username" required><br>
                        <label>Password:</label>
                        <input type="password" name="password" required><br>
                        <input type="submit" value="Signup">
                    </form>
                </body>
                </html>
            """

@app.route('/login', methods=['GET', 'POST'])
def login():
    flashed_messages = get_flashed_messages_html()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username]['password'] == password:
            # Create a session for the user
            user = User(username)
            login_user(user)

            # Step 1: Generate OTP for user
            totp = pyotp.TOTP(users[username]['otp_secret'])
            otp = totp.now()  # Generate the current OTP

            # In real implementation, OTP will be sent via email/SMS. Here we print it for testing:
            flash(f"OTP for {username}: {otp}")

            return redirect(url_for('verify_otp'))
        flash('Invalid username or password.')

    return f""" 
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Login</title>
                </head>
                <body>
                    <h2>Login</h2>
                    {flashed_messages}  <!-- Display flashed messages here -->
                    <form action="{url_for('login')}" method="POST">
                        <label>Username:</label>
                        <input type="text" name="username" required><br>
                        <label>Password:</label>
                        <input type="password" name="password" required><br>
                        <input type="submit" value="Login">
                    </form>
                    <p>Don't have an account? <a href="{url_for('signup')}">Sign up here</a></p>
                </body>
                </html>
                """

@app.route('/verify-otp', methods=['GET', 'POST'])
@login_required
def verify_otp():
    flashed_messages = get_flashed_messages_html()
    if request.method == 'POST':
        otp = request.form['otp']
        totp = pyotp.TOTP(users[current_user.id]['otp_secret'])

        if totp.verify(otp):
            # Step 2: OTP is verified, log the user in
            users[current_user.id]['otp_verified'] = True  # Set OTP verification to True in the users dictionary
            flash('OTP verified successfully!')
            return redirect(url_for('protected'))
        flash('Invalid OTP. Please try again.')

    return f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Verify OTP</title>
                </head>
                <body>
                    <h2>Enter OTP</h2>
                    {flashed_messages}
                    <form action="{url_for('verify_otp')}" method="POST">
                        <label>OTP:</label>
                        <input type="text" name="otp" required><br>
                        <input type="submit" value="Verify OTP">
                    </form>
                </body>
                </html>
                """

@app.route('/protected')
@login_required
def protected():
    if not users[current_user.id]['otp_verified']:
        flash('Please verify your OTP first')
        return redirect(url_for('verify_otp'))
    logout_url = url_for('logout', _external=True)
    return f'Logged in as {current_user.id}. Welcome to the protected page! ; To logout visit <a href=\'{logout_url}\'>Logout</a>'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def public():
    return redirect(url_for('signup'))

if __name__ == '__main__':
    app.run(debug=True)
