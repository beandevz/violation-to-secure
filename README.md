# violation-to-secure

Intentionally vulnerable sample application, used as a fixture for security
scanners and secure-code-review training. **Never deploy this.** All credentials
in it are fake.

## Layout

| File | Violations |
| --- | --- |
| `config/settings.py` | CWE-798 / CWE-259 hard-coded DB password, secret key, API tokens, private key; debug enabled |
| `config/database.yml` | CWE-798 hard-coded per-environment DB, SMTP, Redis credentials; TLS disabled |
| `app/db.py` | CWE-89 SQL injection in SELECT / UPDATE / DELETE / ORDER BY / raw WHERE |
| `app/auth.py` | CWE-89 auth-bypass injection, CWE-256 plaintext passwords, CWE-798 backdoor account |
| `app/main.py` | Flask routes providing the taint sources, CWE-200 secret disclosure endpoint |

## Reproducing the findings

```bash
pip install -r requirements.txt
python -m app.main

# SQL injection: dump every user
curl "http://localhost:8080/users/1%20OR%201=1"

# UNION injection through the search filter
curl -G http://localhost:8080/users/search \
     --data-urlencode "name=x' UNION SELECT id, password, email, role FROM users--"

# Authentication bypass
curl -d "username=admin'--&password=anything" http://localhost:8080/login

# Hard-coded backdoor from config/settings.py
curl -d "username=root&password=admin123" http://localhost:8080/login
```

## Remediation targets

- Replace every concatenated query with parameter binding
  (`conn.execute("SELECT ... WHERE id = ?", (user_id,))`). `ORDER BY` cannot be
  bound — validate it against an allowlist of column names instead.
- Load secrets from environment variables or a secret manager; keep
  `config/*.yml` free of literals and rotate anything already committed.
- Hash passwords with bcrypt/argon2 and drop the hard-coded admin account.
- Turn off `DEBUG`, bind to localhost, and delete `/debug/config`.
