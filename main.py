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

def signin_google():
    flow = InstalledAppFlow.from_client_secrets_file(
        'client_secret.json',
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email']
    )
    creds = flow.run_local_server(port=0)

    id_token = creds.id_token

    print(f"ID Token: {id_token}")

    from google.auth import jwt
    decoded_token = jwt.decode(id_token, verify=False)

    return {
        "id_token": id_token,
        "email": decoded_token.get("email")
    }

print(signin_google().get("email"))