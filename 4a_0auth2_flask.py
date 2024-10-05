from flask import Flask, redirect, url_for, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
#from flask_oauthlib.client import OAuth
from authlib.integrations.flask_client import OAuth
# Initialize Flask app
app = Flask(__name__)

# Set secret key directly in code (development purposes only)
app.secret_key = "your_secret_key"

# Configure OAuth (using hardcoded Google OAuth2 credentials)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id="your google client id",
    client_secret="your google client secret",
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={'scope': 'openid profile email'}
)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Dummy user model for demonstration
class User(UserMixin):
    def __init__(self, id_, name, email):
        self.id = id_
        self.name = name
        self.email = email

# In-memory user store (replace with database in production)
users = {}

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Routes

# Home page route
@app.route('/')
def home():
    return f"""<h1>Home</h1><a href="/login">Login</a>"""

# Login page route
@app.route('/login')
def login():
    return f"""<h1>Login</h1><a href="/login/oauth/google">Login with Google</a>"""

# Google OAuth login route
@app.route('/login/oauth/google')
def login_oauth():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

# Google OAuth authorize route
@app.route('/authorize')
def authorize():
    try:
        # Get the token from OAuth provider (Google)
        token = google.authorize_access_token()
        user_info = google.parse_id_token(token)

        # Extract user info from Google response
        user_id = user_info['sub']
        if user_id not in users:
            # New user signup
            user = User(id_=user_id, name=user_info['name'], email=user_info['email'])
            users[user_id] = user
            login_user(user)
            return redirect(url_for('protected'))

        # Existing user login
        user = users.get(user_id)
        login_user(user)
        return redirect(url_for('protected'))

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Signup page route
@app.route('/signup')
def signup():
    return f"""<h1>Signup</h1><a href="/login">Login with Google</a>"""

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Protected page route (only accessible when logged in)
@app.route('/protected')
@login_required
def protected():
    return f"""<h1>Welcome, {current_user.name}</h1><a href="/logout">Logout</a>"""

# Error handling route (for unauthorized access)
@app.errorhandler(401)
def unauthorized(e):
    return redirect(url_for('login'))

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)

