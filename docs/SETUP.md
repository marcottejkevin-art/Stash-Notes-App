# Stash Setup and Deployment History

This document records the setup completed for the self-hosted Stash instance so the deployment can be rebuilt without relying on chat history.

## 1. Application goal

Stash was built as a simple personal notes application. It organizes account information into searchable categories/folders and is designed to be comfortable to use from a phone.

It is not intended to be a drop-in replacement for a dedicated password manager.

## 2. Host environment

The deployed host uses:

- Ubuntu 26.04.1 LTS
- Python 3.14.1
- User account: the deployment account owns the application directory
- Application directory: `~/stash`
- Python virtual environment: `~/stash/venv`

Create/recreate the virtual environment with:

```bash
cd ~/stash
python3 -m venv venv
source venv/bin/activate
```

Install the required packages:

```bash
pip install flask cryptography gunicorn
```

## 3. Application structure

The important deployment files are:

```text
~/stash/
├── app.py                 # Flask application
├── stash.db               # SQLite database; sensitive
├── stash_config.json      # encryption/auth configuration; sensitive
├── stash_session_secret   # session secret; sensitive
└── venv/                  # Python environment; local deployment state
```

The exact application code is intentionally maintained separately from runtime state. Runtime secrets and database files belong on the host, not in the public Git repository.

## 4. Database and encryption model

Stash stores application records in SQLite.

The following entry fields are encrypted:

- name
- username
- password
- category
- notes

Fernet provides authenticated symmetric encryption. The Fernet key is derived from the master password using PBKDF2-HMAC-SHA256 with:

- 600,000 iterations
- a random 16-byte salt

The salt and password-verification material are stored in `stash_config.json`. The master password itself is not stored.

The master password has a minimum length of 12 characters.

### Important recovery implication

The application database and encryption configuration are a pair. A backup that contains only `stash.db` is not a complete application recovery backup. Keep `stash_config.json` with it. The session secret is also included in the final backup so the deployed application state can be restored consistently.

## 5. Authentication and locking

The deployed application uses a master-password login.

Per-browser login sessions were added so that logging in to one browser does not automatically unlock another browser/session.

The application also has:

- 15-minute automatic locking
- manual Lock control
- password show/hide in the UI

The 15-minute automatic lock was tested during setup.

A separate browser/private browsing session was used to verify that a fresh session requests the master password rather than inheriting the existing browser login.

## 6. User interface work completed

The UI was iteratively refined for desktop and phone use.

Implemented controls and behavior include:

- Stash-branded login page
- mobile-friendly main page
- add-entry form
- search
- category/folder organization
- clickable category headers
- folder collapse/expand arrows
- edit and delete controls below the password section
- password show/hide control
- manual Lock button

The folder-collapse behavior required moving the `toggleCategory` JavaScript into the main page template so it was available where the category controls were rendered. It was then verified working.

Copy buttons were experimented with during development but were intentionally removed from the final UI.

## 7. Production service

Stash runs under Gunicorn through systemd using the service:

```text
stash.service
```

Useful commands:

```bash
sudo systemctl status stash.service
sudo systemctl is-active stash.service
sudo systemctl restart stash.service
```

After a code change, restart the service and verify that it is active.

## 8. Local network binding

The production service is intentionally bound to localhost:

```text
127.0.0.1:5000
```

Verify with:

```bash
sudo ss -lntp | grep ':5000'
```

This prevents direct LAN/Internet access to the application port.

Do not change the bind address to `0.0.0.0` just to make Tailscale access work. Tailscale Serve handles the external access path.

## 9. Tailscale HTTPS

Tailscale was installed on the host and Tailscale Serve was configured to proxy the HTTPS Tailscale hostname to the local Stash service:

```text
HTTPS Tailscale hostname
        ↓
http://127.0.0.1:5000
```

Check the configuration with:

```bash
tailscale serve status
```

The exact personal Tailscale hostname is not documented in this public repository.

Stash was tested successfully from an iPhone using Brave.

## 10. Firewall hardening

UFW was enabled and configured with a deny-by-default incoming policy.

Inspect the current rules with:

```bash
sudo ufw status verbose
```

The deployed configuration permits traffic on the Tailscale interface while leaving port 5000 unexposed directly.

This is preferable to opening port 5000 on the LAN or Internet.

## 11. SSH check

SSH was checked during the hardening pass with:

```bash
sudo systemctl is-active ssh
```

It was inactive at that time.

If SSH is later enabled, review the firewall and SSH authentication configuration as part of that change.

## 12. Final backup

A final backup directory was created on the host:

```text
~/stash-backups/final/
```

The following files were copied into it:

```text
app.py
stash.db
stash_config.json
stash_session_secret
```

A compressed archive was created as:

```text
~/stash-backups/stash-final-backup.tar.gz
```

Because the archive contains sensitive deployment state, an encrypted GPG copy was then created:

```text
~/stash-backups/stash-final-backup.tar.gz.gpg
```

The encrypted file was verified to exist after creation.

The GPG passphrase is separate from the Stash master password and must be stored safely outside the repository.

## 13. Rebuild checklist

For a future rebuild:

1. Install Ubuntu/Python and create `~/stash`.
2. Restore `app.py` from source control or a trusted application backup.
3. Create the virtual environment and install Flask, cryptography, and Gunicorn.
4. Restore `stash.db`, `stash_config.json`, and `stash_session_secret` from a trusted backup.
5. Configure the `stash.service` systemd unit.
6. Start and enable `stash.service`.
7. Confirm the service is listening only on `127.0.0.1:5000`.
8. Install/configure Tailscale and Tailscale Serve.
9. Confirm UFW is enabled and the Tailscale interface is allowed.
10. Test login, data access, automatic lock, and a second browser session.
11. Create a new encrypted backup after the rebuilt instance is confirmed working.

## 14. Things that should never be copied into this repository

Never commit:

- the live SQLite database
- the encryption/auth configuration
- the session secret
- the master password
- the GPG backup passphrase
- personal Tailscale credentials or auth keys
- live backup archives
- `.env` files containing secrets

See `docs/SECURITY.md` for the security model and `docs/BACKUPS.md` for backup handling.
