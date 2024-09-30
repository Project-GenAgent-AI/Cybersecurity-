from flask import Flask, session, request, url_for, make_response
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

# Secret key for session management
app.secret_key = 'your_secret_key_here'

# Dictionary of users and passwords (simulates a user database)
users = {
    "admin": "password123",
    "user1": "mypassword",
}

# Function to verify the username and password provided by the client
@auth.verify_password
def verify_password(username, password):
    if username in users and users[username] == password:
        session['username'] = username  # Store the username in session
        return username
    return None
# Define a route for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    index_url = url_for('index')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return "Username already exists. Please choose a different username."

        # Store the new user's credentials
        users[username] = password
        return (f'Signup successful! home page : <a href=\'{index_url}\'>home page</a>')
    return '''
        <form method="post">
            Username: <input type="text" name="username" required><br>
            Password: <input type="password" name="password" required><br>
            <input type="submit" value="Sign Up">
        </form>
    '''


# Error handler for unauthorized access
@auth.error_handler
def unauthorized():
    return make_response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

# Define a root route for the homepage (no authentication required)
@app.route('/')
def index():
    # Dynamically generate the URL for the /protected route
    protected_url = url_for('protected')
    signup_url = url_for('signup')
    return (f'Welcome to the homepage! Please navigate to <a href=\'{signup_url}\'>sign up </a> to sign up.'
            f' login page : <a href=\'{protected_url}\'> protected page</a>')

# Define a protected route that requires authentication
@app.route('/protected')
@auth.login_required  # Ensures this route is accessible only if the user is authenticated
def protected():
    sensitive_data_url = url_for('sensitive_data')  # Use correct function reference for sensitive data URL
    return (f'Hello, {auth.current_user()}! You have access to the protected content. '
            f'To access sensitive data navigate to <a href=\'{sensitive_data_url}\'>sensitive data</a>.')

# Define another protected route for sensitive data
@app.route('/sensitive-data')
@auth.login_required  # This route also requires authentication
def sensitive_data():
    logout_url = url_for('logout')
    return (f'This is sensitive data that requires authentication! '
            f'To logout visit <a href=\'{logout_url}\'>logout</a>.')

# Logout route that clears the session
@app.route('/logout')
def logout():
    session.clear()  # Clears the session, effectively logging the user out
    # Return a 401 Unauthorized response to prompt for login on next access
    return make_response('You have been logged out. Please log in again.', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

# Running the Flask app
if __name__ == '__main__':
    app.run(debug=True)

