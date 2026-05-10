# SSO-Authentication-Project
SSO-Authentication project
OneKey University Portal - Refined Version

Run:
1. py -3.12 -m pip install -r requirements.txt
2. py -3.12 app.py
3. Open http://127.0.0.1:5000

Google OAuth setup:
Set these environment variables before running if you want real Google sign-in:

Windows CMD:
set GOOGLE_CLIENT_ID=your-client-id
set GOOGLE_CLIENT_SECRET=your-client-secret
py -3.12 app.py

Google Cloud settings:
Authorized JavaScript origin:
http://127.0.0.1:5000

Authorized redirect URI:
http://127.0.0.1:5000/google/callback

Main routes:
/login
/register
/dashboard
/library                 OAuth2-style app
/moodle                  SAML-style app
/student-registration
/faculty
/saml/metadata
