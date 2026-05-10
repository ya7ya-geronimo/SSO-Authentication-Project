══════════════════════════════════════════════════════════════
  OneKey University Portal — Certificate & Network Setup Guide
══════════════════════════════════════════════════════════════

The app now binds to 0.0.0.0 (all interfaces) instead of localhost,
so other devices on your network can reach it.  You just need a
certificate that is valid for your machine's IP address, not just
"localhost".

────────────────────────────────────────────────────────────────
OPTION A — LAN / Other devices on your Wi-Fi  (RECOMMENDED)
────────────────────────────────────────────────────────────────
Tool required: mkcert  (free, one-time install)

Step 1 — Install mkcert
  Windows (with Chocolatey):   choco install mkcert
  Windows (manual):            download from https://github.com/FiloSottile/mkcert/releases
  macOS:                       brew install mkcert
  Linux:                       https://github.com/FiloSottile/mkcert#linux

Step 2 — Install the local CA (one-time, trust on THIS machine)
  mkcert -install

Step 3 — Find your local IP address
  Windows:   ipconfig          → look for "IPv4 Address" e.g. 192.168.1.50
  macOS/Linux: ip addr         → look for "inet" on your Wi-Fi interface

Step 4 — Generate a cert for your IP
  mkcert 192.168.1.50
  (replace with your actual IP)

  This creates:
    192.168.1.50.pem       ← certificate
    192.168.1.50-key.pem   ← private key

Step 5 — Set env vars and run
  Windows CMD:
    set CERT_FILE=192.168.1.50.pem
    set KEY_FILE=192.168.1.50-key.pem
    py -3.12 app.py

  PowerShell:
    $env:CERT_FILE="192.168.1.50.pem"
    $env:KEY_FILE="192.168.1.50-key.pem"
    py -3.12 app.py

Step 6 — Trust the CA on other devices
  Other Windows/Mac devices: copy the mkcert root CA and install it.
  Android/iOS: copy rootCA.pem from mkcert -CAROOT and install as
  "User Certificate" in Settings → Security.

  The root CA file is at the path shown by:
    mkcert -CAROOT

Now open:  https://192.168.1.50:5000  from any device on the network.

────────────────────────────────────────────────────────────────
OPTION B — Public domain / Production  (Let's Encrypt)
────────────────────────────────────────────────────────────────
Requirements: a real domain name, a public server, port 80/443 open.

Step 1 — Install certbot
  Ubuntu:  sudo apt install certbot

Step 2 — Get a certificate
  sudo certbot certonly --standalone -d yourdomain.com

  Certificates are saved to:
    /etc/letsencrypt/live/yourdomain.com/fullchain.pem
    /etc/letsencrypt/live/yourdomain.com/privkey.pem

Step 3 — Run the app
  set CERT_FILE=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
  set KEY_FILE=/etc/letsencrypt/live/yourdomain.com/privkey.pem
  set PORT=443
  python app.py

  Auto-renew:  sudo certbot renew --dry-run

────────────────────────────────────────────────────────────────
OPTION C — Quick LAN test (self-signed, browser warning expected)
────────────────────────────────────────────────────────────────
The existing localhost.pem / localhost-key.pem will work on other
devices ONLY if you manually accept the browser warning on each
device.  Use mkcert (Option A) for a cleaner experience.

════════════════════════════════════════════════════════════════
reCAPTCHA Keys
════════════════════════════════════════════════════════════════
The app uses Google's official TEST keys by default.  They show
the reCAPTCHA widget but always pass — perfect for local demo.

For production, get real keys at:
  https://www.google.com/recaptcha/admin/create
  (choose reCAPTCHA v2 "I'm not a robot")

Then set:
  set RECAPTCHA_SITE_KEY=your-site-key
  set RECAPTCHA_SECRET_KEY=your-secret-key

════════════════════════════════════════════════════════════════
SAML Packet Viewer  (Extra Credit)
════════════════════════════════════════════════════════════════
After logging in, click "SAML Log" in the top nav bar, or visit:
  https://<your-ip>:5000/saml/viewer

Click "Trigger SAML Flow" to start a Moodle login.
You will see:
  • AuthnRequest  — SP→IdP: the XML Moodle sends asking for auth
  • Response/Assertion — IdP→SP: the XML the IdP sends back with
    the user's identity and attributes (NameID, role, email, etc.)

Both are stored decoded so you can read the raw XML.
