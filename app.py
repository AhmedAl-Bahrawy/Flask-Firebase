import os
from flask import Flask, render_template, request, redirect, flash, url_for, jsonify, session
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from authentication import auth
from models import db, UserModel
from typing import Tuple, Optional, Dict, Any, Union
from functools import wraps
import json

# Load environment
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

# ---- Firebase Authentication Helper Functions ----

def create_firebase_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Create a new Firebase user.
    
    Args:
        email: User's email
        password: User's password
        
    Returns:
        Dict with user data if successful, None if failed
    
    Example:
        user_data = create_firebase_user("user@example.com", "password123")
        if user_data:
            # User created successfully
            user_id = user_data["localId"]
    """
    try:
        return auth.create_user_with_email_and_password(email, password)
    except Exception as e:
        print("Error creating Firebase user:", e)
        return None

def send_verification_email(id_token: str) -> bool:
    """
    Send email verification to user.
    
    Args:
        id_token: User's Firebase ID token
        
    Returns:
        True if email sent successfully, False otherwise
        
    Example:
        if send_verification_email(user.idToken):
            flash("Verification email sent!")
    """
    try:
        auth.send_email_verification(id_token)
        return True
    except Exception as e:
        print("Error sending verification email:", e)
        return False

def send_password_reset(email: str) -> bool:
    """
    Send password reset email.
    
    Args:
        email: User's email address
        
    Returns:
        True if reset email sent successfully, False otherwise
        
    Example:
        if send_password_reset("user@example.com"):
            flash("Password reset email sent!")
    """
    try:
        auth.send_password_reset_email(email)
        return True
    except Exception as e:
        print("Error sending password reset:", e)
        return False

# ---- Database Helper Functions ----

def create_local_user(
    local_id: str,
    email: str,
    fname: str,
    lname: str,
    id_token: str,
    refresh_token: str,
    is_google_user: bool = False
) -> Optional[UserModel]:
    """
    Create a new user in the local database.
    
    Args:
        local_id: Firebase user ID
        email: User's email
        fname: First name
        lname: Last name
        id_token: Firebase ID token
        refresh_token: Firebase refresh token
        is_google_user: Whether this is a Google user
        
    Returns:
        Created UserModel instance or None if failed
        
    Example:
        user = create_local_user(
            firebase_user["localId"],
            "user@example.com",
            "John",
            "Doe",
            firebase_user["idToken"],
            firebase_user["refreshToken"]
        )
    """
    try:
        user = UserModel(local_id, email, fname, lname, id_token, refresh_token, is_verified=is_google_user, is_google_user=is_google_user)
        db.session.add(user)
        db.session.commit()
        return user
    except Exception as e:
        print("Error creating local user:", e)
        db.session.rollback()
        return None

def get_user_by_id(user_id: str) -> Optional[UserModel]:
    """
    Get user from local database by ID.
    
    Args:
        user_id: User's ID in local database
        
    Returns:
        UserModel instance or None if not found
        
    Example:
        user = get_user_by_id(firebase_user["localId"])
        if user:
            print(f"Found user: {user.email}")
    """
    return db.session.get(UserModel, user_id)

def update_user_verification(user: UserModel, is_verified: bool) -> bool:
    """
    Update user's verification status.
    
    Args:
        user: UserModel instance
        is_verified: New verification status
        
    Returns:
        True if update successful, False otherwise
        
    Example:
        if update_user_verification(current_user, True):
            flash("Email verified successfully!")
    """
    try:
        user.is_verified = is_verified
        db.session.commit()
        return True
    except Exception as e:
        print("Error updating verification:", e)
        db.session.rollback()
        return False

# ---- Session Management Functions ----

# Database setup
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(UserModel, user_id)

# Token refresh threshold (in seconds)
TOKEN_REFRESH_THRESHOLD = 300  # 5 minutes

def clear_user_tokens() -> None:
    """Clear user tokens from the database."""
    if current_user and hasattr(current_user, 'idToken'):
        current_user.idToken = None
        current_user.refresh_token = None
        db.session.commit()

def should_refresh_token() -> bool:
    """Check if token should be refreshed based on current token validity."""
    if not current_user or not current_user.idToken:
        return True
        
    try:
        # Get account info to check token validity
        info = auth.get_account_info(current_user.idToken)
        return False  # Token is still valid
    except Exception as e:
        error_message = str(e)
        print("Token validation error:", error_message)
        return "TOKEN_EXPIRED" in error_message or "INVALID_ARGUMENT" in error_message

# Helper function to refresh Firebase token
def refresh_firebase_token() -> bool:
    """Attempt to refresh the Firebase token using the refresh token."""
    if not current_user or not current_user.refresh_token:
        clear_user_tokens()
        return False
        
    try:
        refresh_result = auth.refresh(current_user.refresh_token)
        if not refresh_result or 'idToken' not in refresh_result:
            print("Invalid refresh result")
            clear_user_tokens()
            return False
            
        current_user.idToken = refresh_result['idToken']
        if 'refreshToken' in refresh_result:
            current_user.refresh_token = refresh_result['refreshToken']
        db.session.commit()
        return True
    except Exception as e:
        error_message = str(e)
        print("Error refreshing token:", error_message)
        
        # Handle various token error cases
        if any(error in error_message for error in [
            "TOKEN_EXPIRED",
            "INVALID_REFRESH_TOKEN",
            "INVALID_GRANT_TYPE",
            "USER_DISABLED",
            "USER_NOT_FOUND",
            "INVALID_ARGUMENT"
        ]):
            clear_user_tokens()
        return False

def handle_token_expiration() -> Optional[Tuple[bool, str]]:
    """Handle token expiration by attempting to refresh. Returns (success, redirect_url) or None if no action needed."""
    # Check if we should proactively refresh the token
    if should_refresh_token():
        if not refresh_firebase_token():
            # If token refresh fails, it might be due to password change
            flash("Your session has expired (possibly due to a password change). Please log in again.", "info")
            logout_user()
            return False, url_for('login')
    return None

def get_firebase_account_info() -> Optional[Dict[str, Any]]:
    """Get Firebase account info with automatic token refresh handling."""
    try:
        return auth.get_account_info(current_user.idToken)
    except Exception as e:
        if "TOKEN_EXPIRED" in str(e):
            result = handle_token_expiration()
            if result:
                success, _ = result
                if not success:
                    return None
            try:
                return auth.get_account_info(current_user.idToken)
            except Exception as e2:
                print("Error after token refresh:", e2)
                return None
        print("Error getting account info:", e)
        return None

def verify_user_email() -> Optional[Tuple[bool, str]]:
    """Verify user's email status and update database if needed. Returns (success, redirect_url) if action needed."""
    if not current_user or not current_user.idToken:
        flash("Session invalid. Please log in again.", "error")
        logout_user()
        return False, url_for('login')

    try:
        info = get_firebase_account_info()
        if not info:
            clear_user_tokens()
            flash("Session expired. Please log in again.", "info")
            logout_user()
            return False, url_for('login')
            
        users = info.get('users', [])
        if not users:
            clear_user_tokens()
            flash("User information not found. Please log in again.", "error")
            logout_user()
            return False, url_for('login')
            
        is_verified = users[0].get('emailVerified', False)
        if is_verified != current_user.is_verified:
            current_user.is_verified = is_verified
            db.session.commit()
            
        return None
            
    except Exception as e:
        print("Error verifying email:", e)
        clear_user_tokens()
        flash("Authentication error. Please log in again.", "error")
        logout_user()
        return False, url_for('login')

def update_user_tokens(idToken: str, refreshToken: str) -> None:
    """Update user's Firebase tokens in the database."""
    current_user.idToken = idToken
    current_user.refresh_token = refreshToken
    db.session.commit()

# ---- Google Authentication Helper Functions ----

def handle_google_auth_response(id_token: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Handle Google authentication response from Firebase.
    
    Args:
        id_token: Firebase ID token from Google auth
        
    Returns:
        Tuple of (success, error_message, user_data)
    """
    try:
        # Get account info to extract user details
        account_info = auth.get_account_info(id_token)
        
        if not account_info or 'users' not in account_info:
            return False, "Invalid authentication response", None
            
        user_info = account_info['users'][0]
        
        # Extract user data
        user_data = {
            'localId': user_info.get('localId'),
            'email': user_info.get('email'),
            'displayName': user_info.get('displayName', ''),
            'emailVerified': user_info.get('emailVerified', False),
            'idToken': id_token,
            'providerId': user_info.get('providerUserInfo', [{}])[0].get('providerId', '')
        }
        
        # Generate a refresh token by signing in with custom token (workaround)
        try:
            # For Google users, we'll use the existing token and create a mock refresh token
            user_data['refreshToken'] = f"google_refresh_{user_data['localId']}"
        except Exception as refresh_error:
            print("Warning: Could not generate refresh token for Google user:", refresh_error)
            user_data['refreshToken'] = f"google_refresh_{user_data['localId']}"
            
        return True, None, user_data
        
    except Exception as e:
        print("Error handling Google auth:", e)
        return False, "Authentication failed. Please try again.", None

def parse_display_name(display_name: str) -> Tuple[str, str]:
    """
    Parse display name into first and last name.
    
    Args:
        display_name: Full display name from Google
        
    Returns:
        Tuple of (first_name, last_name)
    """
    if not display_name:
        return "User", ""
        
    parts = display_name.strip().split(' ')
    if len(parts) == 1:
        return parts[0], ""
    elif len(parts) >= 2:
        return parts[0], ' '.join(parts[1:])
    else:
        return "User", ""

# ---- Routes ----
@app.route("/", methods=["POST", "GET"])
@login_required
def home():
    # Check if tokens are missing (possibly due to password change)
    if not current_user.idToken or not current_user.refresh_token:
        flash("Your session has expired (possibly due to a password change). Please log in again.", "info")
        logout_user()
        return redirect(url_for('login'))
        
    result = verify_user_email()
    if result:
        success, redirect_url = result
        if not success:
            return redirect(redirect_url)
    
    if not current_user.is_verified and not current_user.is_google_user:
        flash("Please verify your email to access the home page.", "error")
    
    return render_template("index.html", user=current_user)

def handle_firebase_login(email: str, password: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """Handle Firebase login and token refresh. Returns (success, error_message, user_data)"""
    try:
        # Sign in to get initial tokens
        user_data = auth.sign_in_with_email_and_password(email, password)
        
        # Immediately refresh to get fresh tokens
        try:
            refresh_result = auth.refresh(user_data['refreshToken'])
            # Update tokens with refreshed ones
            user_data['idToken'] = refresh_result['idToken']
            user_data['refreshToken'] = refresh_result.get('refreshToken', user_data['refreshToken'])
        except Exception as refresh_error:
            print("Warning: Could not refresh initial token:", refresh_error)
            # Continue with original tokens if refresh fails
            
        return True, None, user_data
    except Exception as e:
        error_message = str(e)
        print("Login error:", error_message)
        if "INVALID_PASSWORD" in error_message:
            return False, "Invalid password. Please try again.", None
        elif "EMAIL_NOT_FOUND" in error_message:
            return False, "Email not found. Please check your email address.", None
        elif "TOO_MANY_ATTEMPTS_TRY_LATER" in error_message:
            return False, "Too many attempts. Please try again later.", None
        return False, "Invalid email or password", None

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        # Handle Firebase authentication
        success, error_message, user_data = handle_firebase_login(email, password)
        if not success:
            flash(error_message, "error")
            return render_template("login.html")
            
        try:
            # Get user info with fresh token
            info = auth.get_account_info(user_data['idToken'])
            
            localId = user_data["localId"]
            idToken = user_data["idToken"]
            refreshToken = user_data["refreshToken"]

            # Check if user exists in DB
            user = db.session.get(UserModel, localId)
            if not user:
                user = UserModel(localId, email, None, None, idToken, refreshToken)
                db.session.add(user)
            else:
                # Update tokens
                user.idToken = idToken
                user.refresh_token = refreshToken
                
            # Verify email status
            email_verified = info['users'][0]['emailVerified']
            user.is_verified = email_verified
            
            # Commit changes before potential redirect
            db.session.commit()
            
            if email_verified:
                login_user(user)
                flash("Login successful", "success")
                return redirect(url_for("home"))
            else:
                flash("Please verify your email before logging in.", "warning")
                return redirect(url_for("login"))

        except Exception as e:
            print("Error processing login:", e)
            db.session.rollback()
            flash("An error occurred during login. Please try again.", "error")
            
    return render_template("login.html")

@app.route("/google-auth", methods=["POST"])
def google_auth():
    """Handle Google authentication from frontend"""
    try:
        data = request.get_json()
        id_token = data.get('idToken')
        
        if not id_token:
            return jsonify({'success': False, 'error': 'No ID token provided'}), 400
            
        # Handle Google authentication
        success, error_message, user_data = handle_google_auth_response(id_token)
        if not success:
            return jsonify({'success': False, 'error': error_message}), 400
            
        localId = user_data["localId"]
        email = user_data["email"]
        display_name = user_data.get("displayName", "")
        email_verified = user_data.get("emailVerified", True)  # Google users are pre-verified
        
        # Parse name
        fname, lname = parse_display_name(display_name)
        
        # Check if user exists in DB
        user = db.session.get(UserModel, localId)
        if not user:
            # Create new Google user
            user = UserModel(
                localId, 
                email, 
                fname, 
                lname, 
                id_token, 
                user_data["refreshToken"],
                is_verified=True,  # Google users are pre-verified
                is_google_user=True
            )
            db.session.add(user)
        else:
            # Update existing user
            user.idToken = id_token
            user.refresh_token = user_data["refreshToken"]
            user.is_verified = True  # Ensure Google users are marked as verified
            if not user.fname and fname:
                user.fname = fname
            if not user.lname and lname:
                user.lname = lname
        
        db.session.commit()
        
        # Log the user in
        login_user(user)
        
        return jsonify({
            'success': True, 
            'redirect': url_for('home'),
            'message': 'Google login successful'
        })
        
    except Exception as e:
        print("Error in Google auth:", e)
        db.session.rollback()
        return jsonify({'success': False, 'error': 'Authentication failed'}), 500

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        cpassword = request.form["cpassword"]
        fname = request.form["fname"]
        lname = request.form["lname"]
        
        # Validate passwords match
        if password != cpassword:
            flash("Passwords do not match", "error")
            return render_template("register.html")

        try:
            # Start a transaction
            firebase_user = None
            try:
                # First try to create the Firebase user
                firebase_user = auth.create_user_with_email_and_password(email, password)

                
                # Send email verification
                auth.send_email_verification(firebase_user['idToken'])

                # If Firebase succeeds, create local user
                localId = firebase_user["localId"]
                idToken = firebase_user["idToken"]
                refreshToken = firebase_user["refreshToken"]

                # Create user in local DB
                user = UserModel(localId, email, fname, lname, idToken, refreshToken)
                db.session.add(user)
                db.session.commit()

                # If everything succeeded, log the user in
                login_user(user)
                return redirect("/verify-info")

            except Exception as inner_e:
                # If local DB fails and Firebase succeeded, try to delete the Firebase user
                if firebase_user:
                    try:
                        auth.delete_user_account(firebase_user['idToken'])
                    except:
                        print("Warning: Could not delete Firebase user after local DB failure")
                
                # Rollback local DB changes
                db.session.rollback()
                
                # Re-raise the exception
                raise inner_e

        except Exception as e:
            print("Register error:", str(e))
            if "EMAIL_EXISTS" in str(e):
                flash("Email already exists", "error")
            else:
                flash("Could not create account. Please try again.", "error")
            
            return render_template("register.html")

    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot-password.html")
    
    if request.method == "POST":
        email = request.form.get("email")
        if not email:
            flash("Please provide your email address.", "error")
            return redirect(url_for("forgot_password"))
        
        try:
            # Send password reset email through Firebase
            auth.send_password_reset_email(email)
            flash("Password reset link has been sent to your email.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            print("Error sending reset email:", e)
            flash("Could not send reset email. Please check your email address.", "error")
            return redirect(url_for("forgot_password"))

@app.route("/verify-info", methods=["GET", "POST"])
@login_required
def verify_info():
    result = verify_user_email()
    if result:
        success, redirect_url = result
        if not success:
            return redirect(redirect_url)
    
    return render_template("verify_info.html", user=current_user)

@app.route("/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    expiry_result = handle_token_expiration()
    if expiry_result:
        success, redirect_url = expiry_result
        if not success:
            return redirect(redirect_url)
            
    try:
        auth.send_email_verification(current_user.idToken)
        flash("Verification email has been sent! Please check your inbox.", "success")
    except Exception as e:
        print("Error sending verification email:", e)
        flash("Could not send verification email. Please try again later.", "error")
    
    return redirect("/verify-info")


def delete_firebase_account(password: str) -> Optional[Tuple[bool, str]]:
    """Delete Firebase account after verifying password. Returns (success, redirect_url) if action needed."""
    try:
        # For Google users, we can't verify password, so skip password verification
        if current_user.is_google_user:
            # For Google users, directly delete using current token
            auth.delete_user_account(current_user.idToken)
            return None
        else:
            # Verify password by attempting to sign in
            user_data = auth.sign_in_with_email_and_password(current_user.email, password)
            # Update tokens with fresh ones
            update_user_tokens(user_data['idToken'], user_data['refreshToken'])
            
            # Delete Firebase account
            auth.delete_user_account(user_data['idToken'])
            return None
    except Exception as e:
        print("Error in delete_firebase_account:", e)
        if "INVALID_PASSWORD" in str(e):
            flash("Incorrect password. Please try again.", "error")
        else:
            flash("Could not delete your account. Please try again later.", "error")
        return False, url_for('delete_account')

@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "GET":
        return render_template("delete-account.html", user=current_user)
        
    if request.method == "POST":
        # For Google users, password is not required
        if not current_user.is_google_user:
            password = request.form.get("password")
            if not password:
                flash("Please provide your password to delete your account.", "error")
                return redirect(url_for('delete_account'))
        else:
            password = None

        # Delete Firebase account first
        result = delete_firebase_account(password)
        if result:
            success, redirect_url = result
            if not success:
                return redirect(redirect_url)

        # If Firebase deletion succeeded, delete from local DB
        try:
            db.session.delete(current_user)
            db.session.commit()
            flash("Your account has been successfully deleted.", "success")
        except Exception as db_error:
            print("Error deleting from database:", db_error)
            flash("Your account was partially deleted. Please contact support.", "error")
        
        logout_user()
        return redirect("/login")
            
    return redirect("/")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=1111)