import pyrebase 

config = {
    'apiKey': "AIzaSyADDXhfQxgj76lNDq2W9-BqlC3XYTOXWp8",
    'authDomain': "flask-auth-c8ce2.firebaseapp.com",
    'projectId': "flask-auth-c8ce2",
    'storageBucket': "flask-auth-c8ce2.firebasestorage.app",
    'messagingSenderId': "50459132624",
    'appId': "1:50459132624:web:a8ff2c906c78d814a314d5",
    'measurementId': "G-K3MJFW9LHF",
    'databaseURL': ''
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()