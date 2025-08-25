from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class UserModel(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.String(128), primary_key=True)   # Firebase localId
    email = db.Column(db.String(255), unique=True, nullable=False)
    idToken = db.Column(db.String(512), nullable=True)
    fname = db.Column(db.String(255), nullable=False)
    lname = db.Column(db.String(255), nullable=False)

    def __init__(self, localId, email, fname, lname, idToken=None):
        self.id = localId
        self.email = email
        self.fname = fname
        self.lname = lname
        self.idToken = idToken
