import pyrebase 
import os
from dotenv import load_dotenv

load_dotenv()


config = {
    'apiKey': os.getenv("API_KEY"),
    'authDomain': os.getenv("AUTH_DOMAIN"),
    'projectId': os.getenv("PROJECT_ID"),
    'storageBucket': os.getenv("STORAGE_BUCKET"),
    'messagingSenderId': os.getenv("MESSAGING_SENDER_ID"),
    'appId': os.getenv("APP_ID"),
    'measurementId': os.getenv("MEASUREMENT_ID"),
    'databaseURL': ''
}

firebase = pyrebase.initialize_app(config)
auth = firebase.auth()