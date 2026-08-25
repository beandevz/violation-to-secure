"""Application configuration.

!!! INTENTIONALLY VULNERABLE SAMPLE - DO NOT USE IN PRODUCTION !!!
Violation: CWE-798 Use of Hard-coded Credentials
           CWE-259 Use of Hard-coded Password
Every secret below should come from an environment variable or a secret
manager, never from a file committed to version control.
"""

# VIOLATION: hard-coded database password
DB_HOST = "prod-db-01.internal.example.com"
DB_PORT = 5432
DB_NAME = "customers"
DB_USER = "app_admin"
DB_PASSWORD = "P@ssw0rd_2024!"  # noqa: S105 - hard-coded credential

# VIOLATION: hard-coded connection string with embedded credentials
DATABASE_URL = "postgresql://app_admin:P@ssw0rd_2024!@prod-db-01.internal.example.com:5432/customers"

# VIOLATION: hard-coded Flask secret key (session forgery)
SECRET_KEY = "dev-secret-key-do-not-change-1234567890"

# VIOLATION: hard-coded third-party API tokens
STRIPE_API_KEY = "sk_live_51H8xQ2KzT9vB3nR7pLmY4wXc"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VIOLATION: hard-coded admin bootstrap account, password in plaintext
ADMIN_USERNAME = "root"
ADMIN_PASSWORD = "admin123"

# VIOLATION: hard-coded private key material
JWT_SIGNING_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3\n-----END RSA PRIVATE KEY-----"

DEBUG = True  # VIOLATION: debug mode enabled in a production config
