from flask import Flask, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from google.oauth2 import id_token
from google.auth.transport import requests
from datetime import datetime, timezone
import enum
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'client_secret.json'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DEV_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
GOOGLE_CLIENT_SECRETS_FILE = 'client_secret.json'
SCOPES = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']

class AuthMethodEnum(enum.Enum):
    EMAIL = "email"
    GOOGLE = "google"

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))  # NULL if using Google
    auth_method = db.Column(db.Enum(AuthMethodEnum, name='auth_method_enum'), nullable=False)
    profile_picture = db.Column(db.String(300))
    date_created = db.Column(db.DateTime, default=datetime.now(timezone.utc))

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')

    if not all([email, password, name]):
        return jsonify({'error': 'Missing fields'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(email=email, name=name, password_hash=hashed_pw, auth_method=AuthMethodEnum.EMAIL)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 200

@app.route('/login', methods=['POST'])
def login_email():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if user.auth_method != AuthMethodEnum.EMAIL:
        return jsonify({'error': 'Use Google login for this account'}), 403

    if not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Incorrect password'}), 401

    session['user'] = {'email': user.email, 'name': user.name}
    return jsonify({'message': 'Logged in successfully'}), 200

@app.route('/login/google')
def login_google():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for('google_callback', _external=True)
    )
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/login/google/callback')
def google_callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=session['state'],
        redirect_uri=url_for('google_callback', _external=True)
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    idinfo = id_token.verify_oauth2_token(creds.id_token, requests.Request(), audience=creds.client_id)

    email = idinfo['email']
    name = idinfo.get('name')
    picture = idinfo.get('picture')

    user = User.query.filter_by(email=email).first()

    if user:
        if user.auth_method == AuthMethodEnum.EMAIL:
            return 'This email is registered with email/password. Use that method.', 403
    else:
        user = User(email=email, name=name, auth_method=AuthMethodEnum.GOOGLE, profile_picture=picture)
        db.session.add(user)
        db.session.commit()

    session['user'] = {'email': user.email, 'name': user.name}
    return redirect('/profile')

@app.route('/profile')
def profile():
    if 'user' not in session:
        return redirect('/')
    return jsonify(session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/auth/status', methods=['GET'])
def check_auth():
    if 'user' in session:
        return jsonify({'status': 'authenticated', 'user': session['user']}), 200
    return jsonify({'status': 'unauthenticated'}), 401

def test_signin_google():
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

def create_tables():
    db.create_all()