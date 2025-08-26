from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class UserModel(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(128), primary_key=True)   # Firebase localId
    email = db.Column(db.String(255), unique=True, nullable=False)
    idToken = db.Column(db.String(512), nullable=True)
    refresh_token = db.Column(db.String(512), nullable=True)  # Added refresh token
    fname = db.Column(db.String(255), nullable=True)  # Made nullable for Google users
    lname = db.Column(db.String(255), nullable=True)  # Made nullable for Google users
    is_verified = db.Column(db.Boolean, default=False)
    is_google_user = db.Column(db.Boolean, default=False)  # Track if user signed up with Google

    def __init__(self, localId, email, fname, lname, idToken=None, refresh_token=None, is_verified=False, is_google_user=False):
        self.id = localId
        self.email = email
        self.fname = fname
        self.lname = lname
        self.idToken = idToken
        self.refresh_token = refresh_token
        self.is_verified = is_verified
        self.is_google_user = is_google_user

    @property
    def display_name(self):
        """Get user's display name for UI"""
        if self.fname and self.lname:
            return f"{self.fname} {self.lname}"
        elif self.fname:
            return self.fname
        elif self.lname:
            return self.lname
        else:
            return self.email.split('@')[0]  # Fallback to email username