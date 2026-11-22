# SentryTrace

SentryTrace is a Django research-data access control project. It uses Django templates, SQLite by default, optional PostgreSQL, TOTP MFA, role-based folder/file ACLs, a forensic hash chain, alerts, compliance exports, and an optional watchdog folder monitor.

## Clean setup (PowerShell)

From the repository root:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:SENTRYTRACE_DEBUG = "true"
$env:SENTRYTRACE_SECRET_KEY = (& .\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))")
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py verify_log --initialize-anchor
.\.venv\Scripts\python.exe manage.py seed_demo
.\.venv\Scripts\python.exe manage.py runserver
```

`seed_demo` prints generated passwords and TOTP keys once, marked **DEMO ONLY**. It does not reset or replace existing demo accounts or their credentials. Save the output for the demo; passwords cannot be recovered later. For a real deployment, do not seed demo accounts.

For an existing database, take a copy of `db.sqlite3` before migrations. The project has been migrated through `authentication.0008_protectedfolder_created_at`; use `manage.py verify_log` after restoring or migrating. Do not initialize a checkpoint against a database whose history has not been reviewed.

The administrator Users page includes standard roles (including **Other**) and lets administrators add organization-specific roles. Role choices are shared by registration approval, account updates, and folder/file access policy forms. Access to protected data is still controlled by the role's explicit ACLs.

## Protected-folder demo sequence

1. Back up `db.sqlite3`, run `python manage.py migrate`, then run `python manage.py seed_demo`. Save the one-time generated credentials and TOTP keys from its **DEMO ONLY** output. Existing accounts with these names are preserved and their credentials are not printed.
2. Start Django with `python manage.py runserver`; open `http://127.0.0.1:8000/login/` and sign in as `admin`. Get the current TOTP with `python manage.py totp_code admin`.
3. Visit `http://127.0.0.1:8000/manage/folders/`. The page lists the real `genomics/` and `outputs/` directories, their permission grids, and a form to create another protected directory. The seeded Researcher permissions are view/edit/no-copy for Genomics and view/edit/copy for Public Outputs.
4. Sign out. Open `http://127.0.0.1:8000/login/`, sign in as `jmwangi`, then run `python manage.py totp_code jmwangi` for the MFA code. Visit `http://127.0.0.1:8000/folders/`, then choose **Browse** beside Genomics Project to open `http://127.0.0.1:8000/folders/<folder-id>/`.
5. Open `genomics_v3.csv` or `notes.txt`. The researcher may edit these files. Attempting to copy a Genomics file is blocked, logged, and raises a high-severity alert. To confirm a permitted copy, use `outputs/survey.csv` and select Public Outputs as its destination; a colliding filename gets a numbered suffix.
6. Sign in again as `admin`; visit `http://127.0.0.1:8000/admin/alerts/` to review the blocked-copy alert. The admin dashboard at `http://127.0.0.1:8000/admin-dashboard/` also summarizes open alerts.
7. Try `kndiritu` from a separate browser; its on-leave status blocks sign-in. `newstaff` remains pending and unassigned. Finish with `python manage.py verify_log`.

The older `demo-admin` / `demo-researcher` demonstration remains available in **Demo Research** and **Demo Output**. Seeded sample files are created only when absent, so rerunning the command does not overwrite file contents.

The generated demo account passwords and TOTP secrets are specific to the database where `seed_demo` was first run. The command prints new values; on repeat runs it preserves accounts and does not reset passwords.

## Management commands

```powershell
python manage.py seed_demo
python manage.py totp_code demo-admin
python manage.py verify_log
python manage.py monitor_folders
```

`monitor_folders --duration 30` is useful for a short local check. The folder monitor writes security events as the non-login `system-monitor` user. App writes set a shared cache marker so the monitor can ignore its own file changes. The default cache is shared by processes on one host using Django's file cache. For multiple hosts, configure `SENTRYTRACE_REDIS_URL` to a shared Redis cache.

## Configuration

| Variable | Purpose |
|---|---|
| `SENTRYTRACE_SECRET_KEY` | Required when `SENTRYTRACE_DEBUG=false`; generated ephemerally for local development if absent. |
| `SENTRYTRACE_DEBUG` | Defaults to `true`; set `false` in production. |
| `SENTRYTRACE_ALLOWED_HOSTS` | Comma-separated host names; required when debug is off. |
| `PROTECTED_DATA_ROOT` | Root directory for protected folders; defaults to `protected_data/`. `SENTRYTRACE_PROTECTED_DATA_ROOT` remains as a supported alias. |
| `SENTRYTRACE_AUDIT_HEAD_FILE` | External audit checkpoint path; defaults to `.sentrytrace-audit-head` beside the project. Keep it outside database backups and protect it separately. |
| `SENTRYTRACE_DATABASE_URL` | Optional PostgreSQL URL (`postgresql://user:password@host:5432/database?sslmode=require`). |
| `SENTRYTRACE_DB_CONN_MAX_AGE` | Optional PostgreSQL persistent connection age in seconds. |
| `SENTRYTRACE_REDIS_URL` | Optional shared Redis cache for rate limits and watcher suppression. |
| `SENTRYTRACE_EMAIL_HOST` | SMTP server hostname; required for email OTP delivery. |
| `SENTRYTRACE_EMAIL_PORT` | SMTP port; defaults to `587`. |
| `SENTRYTRACE_EMAIL_USER` | SMTP account username. |
| `SENTRYTRACE_EMAIL_PASSWORD` | SMTP account password or provider app password. |
| `SENTRYTRACE_EMAIL_USE_TLS` | Use STARTTLS; defaults to `true`. Set `false` when using implicit SSL. |
| `SENTRYTRACE_EMAIL_USE_SSL` | Use implicit SSL; defaults to `false`. Do not enable together with TLS. |
| `SENTRYTRACE_DEFAULT_FROM_EMAIL` | Sender address; defaults to the SMTP username or `sentrytrace@localhost`. |
| `SENTRYTRACE_EMAIL_TIMEOUT` | SMTP timeout in seconds; defaults to `10`. |

When debug is off, Django enables HTTPS redirect, secure session/CSRF cookies, HSTS, content-type sniffing protection, and a same-origin referrer policy. Terminate TLS correctly at the application or configure a trusted reverse proxy. Django's default SQLite database remains available when `SENTRYTRACE_DATABASE_URL` is unset.

### Email OTP local setup

Configure an SMTP mailbox in the environment before starting Django. For example, in PowerShell:

```powershell
$env:SENTRYTRACE_EMAIL_HOST = "smtp.example.com"
$env:SENTRYTRACE_EMAIL_PORT = "587"
$env:SENTRYTRACE_EMAIL_USER = "your-smtp-user"
$env:SENTRYTRACE_EMAIL_PASSWORD = "your-provider-app-password"
$env:SENTRYTRACE_EMAIL_USE_TLS = "true"
$env:SENTRYTRACE_DEFAULT_FROM_EMAIL = "sentrytrace@example.com"
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
```

Sign in with an active account and its password. During MFA setup, choose **Choose email verification**, then enter the code delivered to the account's registered email. For an enrolled user, set **MFA settings → Email verification code** after authenticating with the current MFA method; the change takes effect after the emailed code is verified. Codes expire after five minutes, are single-use, and are rate limited. Do not set `SENTRYTRACE_EMAIL_BACKEND` to Django's console backend because that backend prints email contents, including the OTP, to the server output.

## Permissions and audit design

Administrators have full application-level access. For researchers, an explicit folder deny overrides a file allow, and an explicit file deny overrides a folder allow. A file grant can allow an action when no folder ACL exists; unmatched paths are denied. `edit` grants destination write access for copy operations. Copy requires `can_copy` on the source and `can_edit` on the destination folder. Paths are relative to `PROTECTED_DATA_ROOT`; absolute paths, parent traversal, backslashes, symlinks escaping the root, and invalid destinations are rejected.

`authentication.AccessLog` is the canonical append-only log. Existing `AccessLog` rows were rehashed and the 7 legacy `AuditLog` rows were copied into it by migration 0005; the original `AuditLog` and `FileEventLog` tables remain intact as read-only historical archives. New security events are written only to `AccessLog`. Each entry hashes the prior hash, actor, folder/file path, event, IP, UTC timestamp, details, and outcome. `.sentrytrace-audit-head` checkpoints the current tail so truncation of the last rows can be detected. Initialize this checkpoint once after verifying a trusted database restore, then protect and back it up separately.

## Tests

```powershell
python manage.py check
python manage.py makemigrations --check
python manage.py test
```

## Known limits

- Browser editing is for UTF-8 text files up to 2 MB. Other files can be downloaded if authorized; there is no malware scanning, content-type sandboxing, or OS-level ACL setup.
- The watchdog can report file creation under the watched root, removal, and move-out events. A plain OS copy **from** a protected file to an unwatched location is a read and is not detectable; moving a file to an unwatched place appears only as a removal. Watchdog does not reliably attribute an event to a process or person.
- The external audit checkpoint is on the same host by default. A host administrator able to alter both database and checkpoint can rewrite history; production should copy checkpoints to a separately controlled/WORM or off-host store.
- TOTP secrets are stored in the application database in plaintext. Use encrypted storage and managed key rotation before production deployment.
- Rate-limit and watcher suppression state is shared by FileBasedCache on one host. Multi-host production requires a shared Redis service. Client IP is `REMOTE_ADDR`; configure trusted proxy handling if deployed behind a proxy.
- PostgreSQL settings and psycopg are included, but PostgreSQL could not be integration-tested in this Windows environment because application control blocked the native driver DLL.
- SMTP delivery requires valid environment configuration and a reachable provider. Email delivery was not verified unless a live SMTP test is explicitly reported. No password reset, MFA recovery codes, or external identity provider is configured.
- Commits could not be created because Git is not installed or available in this environment.
