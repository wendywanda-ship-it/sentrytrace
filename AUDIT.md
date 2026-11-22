# SentryTrace project audit

Audit performed on 2026-11-16 before the remaining implementation work. The repository contains the Django project and two apps (`authentication`, `audit_logs`); there is no `reference_sentrytrace/`, README, dependency manifest, or prior audit document. The configured database is SQLite. Current database state: 4 users, 2 `AccessLog` rows, 7 `AuditLog` rows, 0 folder/file ACLs, 0 `FileEventLog` rows, 0 alerts, and 0 reports. `authentication.0004_filepermission` is applied.

## Feature status

| Feature | Status | Current state / gap |
|---|---|---|
| Registration and approval | Partial | Registration makes pending users and hashes passwords. No password confirmation. Approval activates users but cannot assign a role; admin user management is not a purpose-built page. |
| Password authentication | Partial | Django password hashing and validators are used. Failed attempts are unthrottled. |
| MFA / TOTP | Partial | pyotp enrolment and subsequent TOTP check exist with +/-1 window. A secret is saved before confirmation, it is plaintext, there is no rate limit or RFC-vector test, and no session timeout is configured. |
| Account status | Partial | Non-active users are blocked at login, but status does not create an alert and existing sessions are not invalidated when status changes. |
| Administrator / staff / auditor dashboards | Partial | Admin/staff/auditor templates exist. The admin page has pending/active counts and recent events; no sessions, open alerts, or daily-event summary. |
| Server-side roles | Partial | Administrator checks are present; other roles are not consistently scoped. Non-admin dashboard roles default to staff behavior. |
| Folder ACL | Partial | `FolderPermission` has role + folder + view/edit/copy booleans. Actions only record authorization events; they do not operate on protected data. No admin management page. |
| File ACL | Partial | `FilePermission` exists and is migrated, with role + folder + relative path + view/edit/copy booleans. Exact-file authorization and traversal checks exist, but there is no protected-file browser or file I/O. |
| Copy policy | Missing | There is no destination/write check, copy operation, rapid-copy detection, or high-severity copy alert. |
| Audit events | Partial | `AuditLog`, `FileEventLog`, and `AccessLog` are parallel models. New auth events write to `AuditLog`, file decisions write to `FileEventLog`, and the `AccessLog` hash chain is not the source of these events. The existing hash computation omits fields and is not append-only. |
| Alerts and resolution UI | Partial | `Alert` exists and is linked to `AccessLog`; no consistent alert generation or resolve page/action. |
| Anomaly rules | Missing | No off-hours detection or admin-page denial alerts. |
| Folder monitor | Missing | No watchdog dependency or monitor command. |
| Forensic integrity | Partial | Hash fields exist only on `AccessLog`; no backfill migration, immutable guards, verify command, or verification page. |
| Compliance reports | Partial | `Report` model exists; no report form, summary, CSV/PDF generation, or export safety. `reportlab` is not installed in the current environment. |
| Frontend | Partial | Existing pages have inconsistent styles and duplicate inline CSS. No shared base template; messages and forms vary by page. |
| Production settings | Partial | Environment variables exist for secret/debug/hosts, but a development fallback secret remains. Secure cookies, SSL redirect, HSTS, and optional PostgreSQL config are absent. `psycopg2` is installed; watchdog and reportlab are not. |
| Demo / utility commands | Missing | No `seed_demo` or `totp_code` commands. |
| Tests | Partial | 9 existing tests cover basic registration, MFA, roles, folder/file ACL checks, and traversal. They do not cover most requested policies and RFC vectors. |
| Documentation | Missing | No README, NOTES, setup/demo instructions, or known-limitations documentation. |

## Models and fields

| Model | Fields |
|---|---|
| `Role` | `role_id`, `role_name`, `description` |
| `User` | `user_id`, inherited `password`, `full_name`, `staff_id`, `email`, `department`, `username`, `totp_secret`, `mfa_enabled`, `role`, `status`, `created_at`, `last_login` |
| `ProtectedFolder` | `folder_id`, `folder_path`, `project_name`, `owner` |
| `FolderPermission` | `permission_id`, `role`, `folder`, `can_view`, `can_edit`, `can_copy` |
| `FilePermission` | `permission_id`, `role`, `folder`, `file_path`, `can_view`, `can_edit`, `can_copy` |
| `AccessLog` | `log_id`, `user`, `folder`, `event_type`, `file_path`, `ip_address`, `event_time`, `prev_hash`, `entry_hash` |
| `Alert` | `alert_id`, `log`, `alert_type`, `severity`, `status`, `created_at`, `resolved_by` |
| `Report` | `report_id`, `generated_by`, `date_from`, `date_to`, `department`, `created_at` |
| `AuditLog` | `id`, `user`, `action`, `ip_address`, `timestamp`, `details` |
| `FileEventLog` | `id`, `user`, `file_path`, `action_type`, `status`, `timestamp` |

## Existing migration concerns

`audit_logs.0001_initial` already creates `FileEventLog`, while `audit_logs.0002_fileeventlog` attempts to create it again. The latter was made a no-op in the checked-out project so a fresh database can follow the graph; it has already been applied on this database and changing it does not alter this database's schema. `authentication.0004_filepermission` adds the previously requested file ACL table and is already applied here.

## Implementation sequence

1. Preserve the current database with a timestamped backup before any schema migration; audit existing hash rows and clarify the canonical append-only event model.
2. Complete registration, role assignment, TOTP enrollment/verification, lockout throttling, session expiry/status enforcement, and status alerts.
3. Implement protected file storage and exact role/file/folder ACL checks, deny precedence, copy source/destination policy, and alerts.
4. Consolidate security-event writes into the hash-chained log, migrate legacy event rows without data loss, add immutability and integrity verification.
5. Add anomaly rules, alert resolution, watchdog monitor, dashboards, and compliance reports.
6. Add demo/verification commands, PostgreSQL and production settings, consistent templates, README/NOTES, and targeted tests.

The requested commit-per-stage workflow cannot be performed in this environment because `git` is not installed / available in PATH.

## Implementation follow-up

The initial audit above is the read-only baseline. The following work has since been completed:

- Account registration now confirms passwords, runs Django validators, and remains pending until an administrator assigns a role and approves it. Administrators can also update account status and role.
- Password authentication is followed by TOTP verification. New enrollment secrets stay in the server-side session until confirmation. Failed password and MFA attempts are throttled at five per five minutes per IP/username. Sessions expire after 15 minutes; account status is checked on every request.
- Protected folders and files now use `PROTECTED_DATA_ROOT`; the application performs UTF-8 file view/edit, binary download, and protected copy operations. File ACLs override broader grants; explicit denies win; unmatched access is denied. Copy requires source copy permission plus destination edit/write permission.
- `AccessLog` is the canonical append-only security log. Migration 0005 added event details/outcome, rehashed existing access rows, and copied legacy audit/file events without deleting the original archive records. Model/queryset/admin guards prevent ordinary edits/deletes, and a separate head file plus hash chain detects content changes and tail truncation after checkpoint initialization.
- Off-hours, status, protected-file denials, unauthorized admin access, blocked copies, and rapid copies create alerts. The admin can resolve alerts and generate CSV/PDF compliance reports.
- Added watchdog, demo, TOTP and audit-verification commands; shared responsive dark base template; README, NOTES and dependency manifest; production and optional PostgreSQL settings.

Post-migration database state was verified as 4 users, 9 canonical `AccessLog` entries (2 existing access rows + 7 migrated audit rows), 7 preserved legacy `AuditLog` rows, 0 legacy `FileEventLog` rows, 0 file ACL rows, and 0 alerts before new runtime events. The 0005 data migration was applied only after `db.sqlite3.backup-pre-0005-apply-20261116` was created and hash-verified.

Remaining limits are documented in README: PostgreSQL could not be driver-tested because Windows application control blocked the psycopg native DLL; TOTP secrets remain plaintext at rest; watchdog cannot detect reads/copies out of its watched tree or attribute events to a process; and the local external head file requires separate off-host/WORM protection for stronger forensic guarantees. Git is unavailable, so no per-stage commits were created.

The current folder-management follow-up also completed:

- Existing `ProtectedFolder`, `FolderPermission`, and `FilePermission` models were reused. The additive `authentication.0008_protectedfolder_created_at` migration adds the missing folder timestamp; it was applied after creating `db.sqlite3.backup-pre-0008-folder-created-20261116`.
- Admins can add protected directories under the configured root and set folder ACLs in a per-folder role grid. `/manage/folders/` and `/folders/` plus `/folders/<id>/` are named routes; existing routes remain supported. Researchers see only role-authorized folders with view/edit/copy badges.
- Shared file helpers enforce real-path boundaries, bounded reads/writes, and unique copy names. Denied operations are logged and alerted. Copy-denial and third-copy-in-60-seconds alerts use high severity.
- The idempotent seeder now additionally creates the `genomics/` and `outputs/` sample trees and the requested `admin`, `jmwangi`, `kndiritu`, and `newstaff` accounts when their usernames are absent. It preserves existing accounts and sample-file contents.
- The latest verification run passed Django checks, migration consistency, and all 46 tests. `verify_log` reported a valid 56-entry chain at the time of that run. The demo seeder was executed; generated credentials appeared in its one-time command output.

The live `runserver` process did not stay available in this execution environment, so an HTTP browser walkthrough could not be completed. The test suite did render the authenticated management and folder pages and exercised the relevant routes.
