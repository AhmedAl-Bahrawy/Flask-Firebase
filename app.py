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
    return UserModel.query.get(user_id)

# ---- Routes ----
@app.route("/")
@login_required
def home():
    return render_template("index.html", user=current_user)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        try:
            user_data = auth.sign_in_with_email_and_password(email, password)

            localId = user_data["localId"]
            idToken = user_data["idToken"]

            # check if user already exists in DB
            user = UserModel.query.get(localId)
            if not user:
                user = UserModel(localId, email, idToken)
                db.session.add(user)
            else:
                user.idToken = idToken  # update token each login

            db.session.commit()

            login_user(user)
            return redirect("/")
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
                
                # If Firebase succeeds, create local user
                localId = firebase_user["localId"]
                idToken = firebase_user["idToken"]

                # Create user in local DB
                user = UserModel(localId, email, fname, lname, idToken)
                db.session.add(user)
                db.session.commit()

                # If everything succeeded, log the user in
                login_user(user)
                return redirect("/")

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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=1111)
