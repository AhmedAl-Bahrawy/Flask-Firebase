import os
from flask import Flask, render_template, request, redirect, flash
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from authentication import auth
from models import db, UserModel

# Load environment
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev_secret_key")

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

# ---- Routes ----
@app.route("/", methods=["POST", "GET"])
@login_required
def home():
    info = auth.get_account_info(current_user.idToken)
    email_verified = info['users'][0]['emailVerified']
    if email_verified and not current_user.is_verified:
        current_user.is_verified = True
        db.session.commit()
    else:
        if not current_user.is_verified:
            flash("Please verify your email to access the home page.", "error")
    return render_template("index.html", user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        try:
            user_data = auth.sign_in_with_email_and_password(email, password)
            
                        # Refresh to get the latest info
            info = auth.get_account_info(user_data['idToken'])

        
            localId = user_data["localId"]
            idToken = user_data["idToken"]
            refreshToken = user_data.get("refreshToken")  # Get the refresh token

            # check if user already exists in DB
            user = db.session.get(UserModel, localId)
            if not user:
                # If we don't have fname/lname (first login after email registration)
                user = UserModel(localId, email, None, None, idToken, refreshToken)
                db.session.add(user)
            else:
                user.idToken = idToken  # update token each login
                user.refresh_token = refreshToken  # update refresh token
                
            # Check if email is verified
            email_verified = info['users'][0]['emailVerified']
            
            
            if email_verified:
                login_user(user)
                flash("Login successful", "success")
                return redirect("/")
            else:
                flash("Email not verified", "error")

            db.session.commit()

            
        except Exception as e:
            print("Login error:", e)
            flash("Invalid email or password", "error")
    return render_template("login.html")

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

@app.route("/verify-info", methods=["GET", "POST"])
@login_required
def verify_info():
    try:
        # Get fresh user info from Firebase
        account_info = auth.get_account_info(current_user.idToken)
        users = account_info.get('users', [])
        if users:
            is_verified = users[0].get('emailVerified', False)
            # Update the user model if needed
            if is_verified != getattr(current_user, 'is_verified', False):
                current_user.is_verified = is_verified
                db.session.commit()
    except Exception as e:
        print("Error checking verification status:", e)
        is_verified = getattr(current_user, 'is_verified', False)
    
    return render_template("verify_info.html", user=current_user)

@app.route("/resend-verification", methods=["POST"])
@login_required
def resend_verification():
    try:
        # Get a fresh ID token first
        refresh_result = auth.refresh(current_user.idToken)
        new_token = refresh_result['idToken']
        
        # Update user's token in database
        current_user.idToken = new_token
        db.session.commit()
        
        # Send verification email
        auth.send_email_verification(new_token)
        flash("Verification email has been sent! Please check your inbox.", "success")
    except Exception as e:
        print("Error sending verification email:", e)
        flash("Could not send verification email. Please try again later.", "error")
    
    return redirect("/verify_info")


@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    if request.method == "POST":
        try:
            # First try to delete from Firebase
            try:
                """
                if not current_user.refresh_token:
                    # Try to get a new refresh token by signing in again
                    try:
                        password = request.form.get("password")
                        if not password:
                            flash("Please provide your password to delete your account.", "error")
                            return redirect("/")
                            
                        # Try to sign in to get fresh tokens
                        user_data = auth.sign_in_with_email_and_password(current_user.email, password)
                        current_user.refresh_token = user_data.get("refreshToken")
                        current_user.idToken = user_data.get("idToken")
                        db.session.commit()
                    except Exception as e:
                        print("Error getting new tokens:", e)
                        flash("Invalid password. Please try again.", "error")
                        return redirect("/")"""
                
                # Get fresh token using refresh token
                refresh_result = auth.refresh(current_user.refresh_token)
                new_token = refresh_result['idToken']
                auth.delete_user_account(new_token)
            except Exception as firebase_error:
                print("Error deleting Firebase account:", firebase_error)
                flash("Could not delete your account. Please try again.", "error")
                return redirect("/")

            # If Firebase deletion succeeded, delete from local DB
            try:
                db.session.delete(current_user)
                db.session.commit()
            except Exception as db_error:
                print("Error deleting from database:", db_error)
                # Note: Firebase account is already deleted at this point
                flash("Your account was partially deleted. Please contact support.", "error")
                logout_user()
                return redirect("/login")

            # If everything succeeded
            flash("Your account has been successfully deleted.", "success")
            logout_user()
            return redirect("/login")

        except Exception as e:
            print("Unexpected error during account deletion:", e)
            flash("An unexpected error occurred. Please try again later.", "error")
            return redirect("/")
            
    # GET requests should not be allowed
    return redirect("/")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=1111)
