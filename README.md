# securenotes

A small notes application built to demonstrate **secure coding**. The feature
set is deliberately tiny — register, log in, write notes. The point is *how*
it is built.

Every control a real application needs is present, and each one is commented in
the source with the attack it stops. No web framework, no ORM, no dependencies:
`http.server`, `sqlite3`, `hashlib`, `secrets`.

## The controls, and what each one stops

| Control | Implementation | Attack prevented |
| --- | --- | --- |
| **Password storage** | PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte per-user salt | Offline cracking after a database breach; rainbow tables |
| **Password comparison** | `secrets.compare_digest` | Timing side channel |
| **Session tokens** | 32 bytes from `secrets`, stored **hashed** (SHA-256) | Token prediction; a database leak yields no usable sessions |
| **Session fixation** | A fresh session id is issued on every login | Session fixation |
| **Cookies** | `HttpOnly`, `SameSite=Strict`, `Secure` (with `--secure-cookies`) | Cookie theft via XSS; cross-site request forgery |
| **CSRF** | Per-session token on every state-changing form, constant-time compare | Cross-site request forgery |
| **SQL** | Parameterised queries everywhere | SQL injection |
| **Output** | `html.escape()` on every interpolated value | Cross-site scripting |
| **CSP** | `default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'` | XSS payload execution; clickjacking |
| **Authorisation** | `user_id` in the `WHERE` clause of every object query | Insecure direct object reference (IDOR) |
| **Login throttling** | 5 failures locks the account for 15 minutes | Credential brute forcing |
| **User enumeration** | One generic error for every failure, plus a dummy hash computation on unknown users | Account discovery via message or timing differences |
| **Input validation** | Length and character-class limits on every field | Resource abuse; malformed data |

## Verified behaviour

These are the actual results of exercising the running application:

```
XSS payload in a note title   -> rendered as &lt;script&gt;, 0 raw script tags
POST with no CSRF token       -> 403
POST with a wrong CSRF token  -> 403
Deleting another user's note  -> no effect, note still present  (IDOR blocked)
6th failed login              -> 429, account locked
Login as a nonexistent user   -> "Invalid username or password." (same as wrong password)
Session cookie                -> HttpOnly, SameSite=Strict
```

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
python3 securenotes.py

# Behind a TLS-terminating reverse proxy
python3 securenotes.py --secure-cookies --bind 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000>.

| Flag | Description | Default |
| --- | --- | --- |
| `-d`, `--database` | SQLite database path | `securenotes.db` |
| `--port` | Port to listen on | `8000` |
| `--bind` | Bind address | `127.0.0.1` |
| `--secure-cookies` | Set `Secure` on cookies and send HSTS | off |

## Deliberate non-goals

**Notes are not encrypted at rest.** The Python standard library has no
authenticated cipher, and rolling one by hand is exactly the mistake this
project exists to argue against. Encrypting the database belongs at the storage
layer (LUKS, SQLCipher, a managed KMS), not in hand-written application code.
Saying so is the honest engineering answer.

**There is no TLS in the server itself.** Terminate TLS at a reverse proxy and
run with `--secure-cookies`. `http.server` is not a hardened production server;
this application is a teaching artefact, not a deployment target.

## Reading the source

`securenotes.py` is organised so each concern is easy to find:

- `Database` — schema and every parameterised query
- `hash_password` / `token_digest` — the crypto helpers
- `validate_registration` — input validation
- the view functions — every value escaped at the point of rendering
- `make_handler` — headers, cookies, CSRF checking, routing, and the actions

## License

MIT — see [LICENSE](LICENSE).
