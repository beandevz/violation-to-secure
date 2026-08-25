"""5 hard-coded credential issues (CWE-798 / CWE-321 / OWASP A07). Fake values."""

DB_PASSWORD = "P@ssw0rd123!"                              # 1. DB password
DB_URI = "postgresql://admin:P@ssw0rd123!@db.example.com:5432/appdb"

AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 2. cloud key

JWT_SIGNING_KEY = "hs256-shared-secret-2019"              # 3. crypto signing key

ADMIN_USER, ADMIN_PASS = "root", "admin123"               # 4. backdoor account


def login(user, password):                                # 5. credential in code path
    return user == ADMIN_USER and password == "admin123"
