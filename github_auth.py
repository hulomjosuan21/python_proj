import requests
import webbrowser
from urllib.parse import urlencode, parse_qs
from http.server import HTTPServer, BaseHTTPRequestHandler

CLIENT_ID = 'Ov23liyuo342J3FHj8II'
CLIENT_SECRET = 'b94cc2c24f7cfa4ff1fa89d755e3869a57421c'
REDIRECT_URI = 'http://localhost:8000/callback'

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '?' not in self.path:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Missing code in callback URL')
            return

        params = parse_qs(self.path.split('?', 1)[1])
        code = params.get('code', [None])[0]
        if code is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Missing code parameter')
            return

        self.server.auth_code = code
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'You can close this window now.')

def signin_github():
    # Step 1: Redirect to GitHub auth
    auth_url = 'https://github.com/login/oauth/authorize?' + urlencode({
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'read:user user:email'
    })
    webbrowser.open(auth_url)

    # Step 2: Handle callback and extract code
    httpd = HTTPServer(('localhost', 8000), OAuthHandler)
    httpd.handle_request()
    code = httpd.auth_code

    # Step 3: Exchange code for token
    token_res = requests.post('https://github.com/login/oauth/access_token', data={
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }, headers={'Accept': 'application/json'})

    access_token = token_res.json().get('access_token')

    # Step 4: Use token to get user info
    user_res = requests.get('https://api.github.com/user', headers={
        'Authorization': f'token {access_token}'
    })

    user_data = user_res.json()

    return {
        "access_token": access_token,
        "username": user_data.get("login"),
        "email": user_data.get("email")  # Might be None if email is private
    }

result = signin_github()
print(result)