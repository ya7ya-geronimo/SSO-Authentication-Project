OneKey HTTPS + Google Login

Run:
1) Double click run_https_google.bat
2) Paste your NEW Google Client Secret when asked
3) Open: https://127.0.0.1:5000
4) Browser may show a certificate warning because this is a local self-signed HTTPS certificate. Click Advanced / Proceed.

Google Cloud required URLs:
Authorized JavaScript origins:
https://127.0.0.1:5000

Authorized redirect URIs:
https://127.0.0.1:5000/google/callback

Keep the HTTP URLs too if you still test on HTTP:
http://127.0.0.1:5000
http://127.0.0.1:5000/google/callback
