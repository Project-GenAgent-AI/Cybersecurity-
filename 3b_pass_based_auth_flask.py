from flask import Flask, request, jsonify, url_for, session
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management
auth = HTTPBasicAuth()  # Create an instance of HTTPBasicAuth for authentication
users = {}  # Dictionary to store username and hashed passwords


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    # Handle signup logic
    if request.method == 'POST':  # Check if the request method is POST
        login_url = url_for('login')  # Get the login URL
        username = request.form.get('username')  # Get the username from the form
        password = request.form.get('password')  # Get the password from the form

        # Check if username and password are provided
        if not username or not password:
            return f"""username and password required !!"""

        # Check if the username already exists
        if username in users:
            return f""" this username already exists """

        # Store the hashed password for the username
        users[username] = generate_password_hash(password)

        # Return a success message with a link to log in
        return f"""you have signed up successfully, 
                        To Log in navigate to <a href=\'{login_url}\'> Log In </a> """

    # Handle GET request to display the signup form
    return f"""<form action="/signup" method="post">
                    Username: <input type="text" name="username"><br>
                    Password: <input type="password" name="password"><br>
                    <input type="submit" value="Sign up">
                </form>"""


@app.route('/login', methods=['POST', 'GET'])
def login():
    # Handle login logic
    if request.method == 'POST':  # Check if the request method is POST
        protected_url = url_for('protected')  # Get the protected URL
        username = request.form.get('username')  # Get the username from the form
        password = request.form.get('password')  # Get the password from the form

        # Check if username and password are provided
        if not username or not password:
            return f""" password and username required"""

        # Retrieve the hashed password from the users dictionary
        user_hashed_password = users.get(username)

        # Verify the password against the stored hashed password
        if user_hashed_password and check_password_hash(user_hashed_password, password):
            session['username'] = username  # Store the username in the session
            return f"""Login successful, 
                            To access protected navigate to <a href=\'{protected_url}\'> Protected page </a> """
        else:
            return f""" Invalid Credentials """

    # Handle GET request to display the login form
    return f"""<form action="/login" method="post">
                    Username: <input type="text" name="username"><br>
                    Password: <input type="password" name="password"><br>
                    <input type="submit" value="Log In">
                </form>"""


@app.route('/protected')
def protected():
    logout_url = url_for('logout')  # Get the logout URL
    # Check if the user is logged in (username in session)
    if 'username' in session:
        return f""" hello {session['username']} , you are viewing a protected route ,
                        To log out navigate to <a href=\'{logout_url}\'> Log Out </a> """
    else:
        # If not logged in, return a message in JSON format
        return jsonify({"message": "please login to view this page"})


@app.route('/logout')
def logout():
    public_url = url_for('public')  # Get the public URL
    session.pop('username', None)  # Remove the username from the session
    return f"""You have logged out successfully , 
                    <a href=\'{public_url}\'> Home Page </a> """


@app.route('/')
def public():
    # Get URLs for signup and login
    signup_url = url_for('signup')
    login_url = url_for('login')

    # Return a message with links to signup and login
    return f"""this is a public route , no authentication required ,
         To sign up navigate to <a href=\'{signup_url}\'>Sign up </a> 
         To Log in navigate to <a href=\'{login_url}\'> Log In </a> """


# Run the application in debug mode
if __name__ == "__main__":
    app.run(debug=True)
