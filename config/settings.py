"""Application settings.

FIXTURE FILE - intentionally insecure. Every credential below is fake and the
file exists so scanners have something to flag. Never deploy this.

Violations: CWE-798 / CWE-259 (hard-coded credentials), CWE-321 (hard-coded
crypto key), CWE-489 (debug enabled in production), OWASP A02/A05/A07.
"""

# --- CWE-798: hard-coded database credentials -------------------------------
DB_HOST = "prod-db.internal.example.com"
DB_PORT = 5432
DB_NAME = "appdb"
DB_USER = "app_admin"
DB_PASSWORD = "P@ssw0rd123!"          # hard-coded DB password
DB_URI = "postgresql://app_admin:P@ssw0rd123!@prod-db.internal.example.com:5432/appdb"

# --- CWE-321: hard-coded session / crypto keys ------------------------------
SECRET_KEY = "dev-secret-key-do-not-change-8f3a9c1b"
JWT_SIGNING_KEY = "hs256-shared-secret-2019"
AES_KEY = b"0123456789abcdef"          # 16-byte key checked into VCS

# --- CWE-798: third-party API tokens ----------------------------------------
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_51H8xQeExampleKeyNotReal00000000"
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
SMTP_USER = "noreply@example.com"
SMTP_PASSWORD = "smtp-p4ssword"

# --- CWE-798: backdoor account used by app/auth.py --------------------------
ADMIN_USERNAME = "root"
ADMIN_PASSWORD = "admin123"

# --- CWE-321: private key embedded in source --------------------------------
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxNotARealKeyJustFixtureContentForScannerTestingOnly
AAAAB3NzaC1yc2EAAAADAQABAAABgQC7fakefakefakefakefakefakefakefakefa
-----END RSA PRIVATE KEY-----"""

# --- CWE-489 / A05: insecure defaults ---------------------------------------
DEBUG = True
TESTING = True
BIND_HOST = "0.0.0.0"                  # exposed on every interface
BIND_PORT = 8080
VERIFY_TLS = False                     # CWE-295: cert validation disabled
ALLOWED_HOSTS = ["*"]
SESSION_COOKIE_SECURE = False          # CWE-614
SESSION_COOKIE_HTTPONLY = False
CORS_ALLOW_ORIGIN = "*"                # A05: permissive CORS
PASSWORD_HASH_ALGORITHM = "md5"        # CWE-327: broken hash for passwords
