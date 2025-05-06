import os
import io
import qrcode
import base64
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret")
app.config['SESSION_COOKIE_NAME'] = 'qr_session'

oauth = OAuth(app)
google = oauth.register(
    name='siva',
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

@app.route('/')
def home():
    if 'user' in session:
        return render_template('index.html', usage=len(session.get('qr_data', [])))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user = google.parse_id_token(token)
    session['user'] = user
    session['qr_data'] = []
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/generate', methods=['POST'])
def generate_qr():
    if 'user' not in session:
        return redirect(url_for('login'))

    data = request.json
    urls = data.get('urls', [])
    used = len(session.get('qr_data', []))

    if used + len(urls) > 30:
        return jsonify({'error': 'QR limit exceeded (30 max).'}), 403

    generated = []
    for item in urls:
        name = item['name']
        url = item['url']
        qr = qrcode.make(url)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
        image_data = f"data:image/png;base64,{encoded}"
        session['qr_data'].append({'name': name, 'url': url})
        generated.append({'name': name, 'url': url, 'image': image_data})

    return jsonify({'results': generated, 'used': len(session['qr_data'])})

@app.route('/usage')
def usage():
    return jsonify({'used': len(session.get('qr_data', [])), 'limit': 30})
