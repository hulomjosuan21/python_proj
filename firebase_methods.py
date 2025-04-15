import firebase_admin
from firebase_admin import credentials, auth
from google_auth_oauthlib.flow import InstalledAppFlow

cred = credentials.Certificate("firebase-adminsdk.json")
firebase_admin.initialize_app(cred)

def get_user():
    user = auth.get_user_by_email(input("Email:").replace(' ', ''))

    return {
        "uid": user.uid,
        "user": user.email,
    }

def update_user():
    user = auth.get_user_by_email(input("Email:").replace(' ', ''))
    disabled = True
    auth.update_user(
        user.uid,
        disabled=disabled
        # some fields
    )
