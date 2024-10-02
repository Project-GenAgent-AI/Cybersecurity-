from flask import Flask, request, jsonify, url_for, session
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import pytz

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management
auth = HTTPBasicAuth()  # Create an instance of HTTPBasicAuth for authentication
users = {}  # Dictionary to store username and hashed passwords
# JWT configuration
JWT_SECRET = 'your_jwt_secret'  # Set your secret key for JWT encoding and decoding


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    # Handle signup logic
    if request.method == 'POST':  # Check if the request method is POST
        username = request.form.get('username')  # Get the username from the form
        password = request.form.get('password')  # Get the password from the form

        # Check if username and password are provided
        if not username or not password:
            return jsonify({"message": "username and password required !!"})

        # Check if the username already exists
        if username in users:
            return jsonify({"message": "this username already exists"})

        # Store the hashed password for the username
        users[username] = generate_password_hash(password)

        # Return a success message with a link to log in
        return jsonify({
            "message": "You have signed up successfully.",
            "login_url": url_for('login', _external=True)  # Use _external=True to create an absolute URL
        })

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

        username = request.form.get('username')  # Get the username from the form
        password = request.form.get('password')  # Get the password from the form

        # Check if username and password are provided
        if not username or not password:
            return jsonify({"message": "password and username required"})

        # Retrieve the hashed password from the users dictionary
        user_hashed_password = users.get(username)

        # Verify the password against the stored hashed password
        if user_hashed_password and check_password_hash(user_hashed_password, password):
            # Create a timezone-aware UTC datetime object
            utc_timezone = pytz.utc
            # Generate the JWT token with an expiration time
            token = jwt.encode({
                'username': username,
                'exp': datetime.datetime.now(utc_timezone) + datetime.timedelta(minutes=30)
            }, JWT_SECRET, algorithm='HS256')
            protected_url = url_for('protected', token=token, _external=True)  # Get the protected URL
            # Return the token and a link to the protected page
            return jsonify({
                "message": "Login successful!",
                "token": token,
                "protected_url": protected_url  # Include absolute URL
            })
        else:
            return jsonify({"message": "Invalid Credentials"})

    # Handle GET request to display the login form
    return f"""<form action="/login" method="post">
                    Username: <input type="text" name="username"><br>
                    Password: <input type="password" name="password"><br>
                    <input type="submit" value="Log In">
                </form>"""


@app.route('/protected')
def protected():
    # Get the token from the request arguments
    token = request.args.get('token')  # Retrieve the token from the URL parameters


    # Check if the token is provided
    if token:
        try:
            # Decode the token
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            username = decoded_token['username']  # Get the username from the decoded token

            return jsonify({
                "message": f"Hello {username}, you are viewing a protected route.",

            }), 200
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401  # Token expired error
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401  # Invalid token error
    else:
        return jsonify({"message": "Token is missing"}), 401  # Token missing error


@app.route('/')
def public():
    # Return a message with links to signup and login
    return jsonify({
        "message": "This is a public route, no authentication required.",
        "signup_url": url_for('signup', _external=True),  # Include absolute URL
        "login_url": url_for('login', _external=True)  # Include absolute URL
    })


# Run the application in debug mode
if __name__ == "__main__":
    app.run(debug=True)

