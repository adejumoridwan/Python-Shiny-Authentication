from shiny import App, reactive, render, ui, run_app
import jwt
import datetime
import hashlib
import hmac
import base64
from functools import wraps

# Secret key for JWT encoding/decoding
SECRET_KEY = "your-secret-key-for-jwt"

# Simple password hashing function using HMAC
def hash_password(password, salt=None):
    if salt is None:
        # Generate a random salt - converting to bytes
        salt = base64.b64encode(hashlib.sha256(str(datetime.datetime.now().timestamp()).encode()).digest())
    
    # Create an HMAC using SHA-256
    hash_obj = hmac.new(salt, password.encode('utf-8'), hashlib.sha256).digest()
    return {"hash": hash_obj, "salt": salt}

# Verify a password against a stored hash
def verify_password(stored_password, provided_password):
    hash_obj = hmac.new(stored_password["salt"], provided_password.encode('utf-8'), hashlib.sha256).digest()
    return hash_obj == stored_password["hash"]

# Pre-hash the password for our mock user
hashed_password = hash_password("password123")

# Mock user database with hashed passwords
USERS = {
    "user@example.com": {
        "password": hashed_password,
        "name": "Demo User"
    }
}

# UI for login page
login_ui = ui.div(
    ui.card(
        ui.card_header("Login"),
        ui.input_text("email", "Email", placeholder="Enter your email"),
        ui.input_password("password", "Password", placeholder="Enter your password"),
        ui.div(
            ui.output_ui("login_message"),
            style="color: red; margin-top: 10px;"
        ),
        ui.input_action_button("login_btn", "Login", class_="btn-primary"),
        width="400px",
        style="margin: 0 auto; margin-top: 100px;"
    )
)

# UI for protected content
protected_ui = ui.div(
    ui.card(
        ui.card_header(ui.output_text("welcome_message")),
        ui.p("This is protected content that requires authentication."),
        ui.input_action_button("logout_btn", "Logout", class_="btn-danger"),
        width="800px",
        style="margin: 0 auto; margin-top: 50px;"
    )
)

# Main UI that will switch between login and protected content
app_ui = ui.page_fluid(
    ui.panel_title("JWT Authentication Example"),
    ui.output_ui("main_content")
)

def server(input, output, session): 
    # Store the JWT token
    token_value = reactive.value(None)
    
    # Function to generate JWT token
    def generate_token(email):
        payload = {
            'email': email,
            'name': USERS[email]['name'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }
        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    
    # Function to verify JWT token
    def verify_token(token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    @render.ui
    def main_content():
        """Render either login UI or protected content based on authentication status"""
        if token_value() is None:
            return login_ui
        else:
            # Verify token before showing protected content
            payload = verify_token(token_value())
            if payload:
                return protected_ui
            else:
                # Token is invalid or expired
                token_value.set(None)
                return login_ui
    
    @render.ui
    def login_message():
        """Display login error messages"""
        if input.login_btn() > 0:
            email = input.email()
            password = input.password()
            
            # Basic validation
            if not email or not password:
                return ui.p("Please enter both email and password")
            
            # Check credentials
            if email not in USERS:
                return ui.p("Invalid email or password")
            
            # Verify password
            if not verify_password(USERS[email]["password"], password):
                return ui.p("Invalid email or password")
            
            # Generate token on successful login
            token_value.set(generate_token(email))
            return ui.p("")
        return ui.p("")
    
    @render.text
    def welcome_message():
        """Welcome message for authenticated user"""
        if token_value() is not None:
            payload = verify_token(token_value())
            if payload:
                return f"Welcome, {payload['name']}"
        return ""
    
    @reactive.effect
    @reactive.event(input.logout_btn) 
    def _():
        """Handle logout"""
        token_value.set(None)

app = App(app_ui, server)
