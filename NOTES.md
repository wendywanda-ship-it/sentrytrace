# Data dictionary notes

This project uses an application-specific schema rather than Django's standard `auth.User`, `Group`, and `Permission` tables for its user-facing roles.

| Project schema | Difference from a common/standard design |
|---|---|
| `authentication.User` | Custom `AbstractBaseUser` with `user_id` integer PK and staff identity fields; `username` is the login identifier. Django's standard first/last name fields are replaced by `full_name`. `status` is a workflow state; approved account state is `active`. |
| `authentication.Role` | A custom role lookup table instead of Django `Group`. Access policy is role-based and does not use Django's per-model permission rows. |
| `authentication.User.role` | One nullable foreign key means each account has one role at a time; a many-to-many role assignment is not modeled. |
| `authentication.ProtectedFolder` | Stores `folder_id`, `project_name`, nullable `owner`, `created_at`, and a unique relative `folder_path` under `PROTECTED_DATA_ROOT`; it does not store an arbitrary absolute OS path. Migration 0008 adds the timestamp without replacing existing folder rows. |
| `authentication.FolderPermission` | One ACL per role and folder; `can_view`, `can_edit`, and `can_copy` are booleans. An existing row with a false action flag is an explicit deny. Absence falls through to file-level ACL, then deny. |
| `authentication.FilePermission` | One ACL per role, folder, and relative file path. File paths are not normalized into a separate `ProtectedFile` table; they refer to files on disk. Explicit false flags deny even when a broader ACL allows the action. |
| `authentication.AccessLog` | Custom append-only forensic table instead of Django's admin log. `prev_hash` / `entry_hash` form the SHA-256 chain; `outcome` labels OK, FLAGGED, or BLOCKED. The separate external head file helps detect tail truncation. |
| `audit_logs.AuditLog` and `audit_logs.FileEventLog` | Kept as historical archive tables to preserve prior records; migration 0005 copied their existing rows into canonical `AccessLog`. New security events do not write to these tables. |
| `authentication.Alert.log` | One-to-one relationship permits at most one alert per canonical log event. Alert resolution/status is mutable; the event itself is immutable. |
| `authentication.Report` | Stores report parameters and generator, not rendered report file contents. CSV/PDF are generated on demand. |
| TOTP secret | `User.totp_secret` is a plaintext model column. A pending key for a new enrollment is held in the session until valid confirmation, but at-rest encryption is not implemented. |

## Permission precedence

For an administrator, the application grants all ACL-checked operations. For every other user, if the role has a folder ACL, a false folder flag denies that action even if a file ACL allows it. Otherwise, a matching file ACL controls the action: true allows and false denies. If a file ACL does not exist, a true folder ACL flag allows. No matching allow is a deny. Copy also needs destination-folder `can_edit`; an allow on the source never grants destination write access. The admin folder grid writes one folder-per-role ACL row, including explicit false flags; the per-file ACL remains a separate, more specific policy layer.

## Operational limits

Protected file paths are resolved under one configured root and checked against symlink escapes. Watchdog notices file-system events but cannot identify a process or detect reads/copies out of the watched tree. The default audit checkpoint is local and must be protected independently for stronger forensic assurance.
