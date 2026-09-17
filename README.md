# Stash Notes App

Stash is a small, self-hosted personal notes application built for keeping organized records such as account usernames, passwords, categories, and notes. It is intentionally a **notes app**, not a full password-manager replacement.

Because Stash can contain real credentials, the deployed version includes encryption, authentication, session isolation, automatic locking, HTTPS access through Tailscale, firewall hardening, and encrypted backups.

## Current deployment

- **Host OS:** Ubuntu 26.04.1 LTS
- **Python:** 3.14.1
- **Framework:** Flask 3.1.3
- **Database:** SQLite
- **Application server:** Gunicorn
- **Service manager:** systemd (`stash.service`)
- **External access:** Tailscale Serve with HTTPS
- **Application bind address:** `127.0.0.1:5000`
- **Firewall:** UFW
- **Mobile client tested:** iPhone using Brave

The application is deliberately bound to localhost. Tailscale Serve provides the HTTPS entry point instead of exposing Flask/Gunicorn directly on the LAN or Internet.

## Features implemented

### Notes and organization

- Add, edit, and delete entries.
- Store name, username, password, category, and notes.
- Search entries.
- Organize entries into categories/folders.
- Clickable folder headers with collapse/expand arrows.
- Password show/hide control.
- Mobile-friendly, app-like interface.
- Stash-branded login and main interface.
- Manual Lock button.

### Authentication and security

- Master-password login.
- Master password is not stored directly.
- Minimum master-password length is 12 characters.
- Password verification uses a stored verifier and a random salt.
- Entry fields are encrypted with Fernet.
- Encryption key is derived from the master password using PBKDF2-HMAC-SHA256 with 600,000 iterations and a random 16-byte salt.
- Encrypted fields include name, username, password, category, and notes.
- Per-browser login sessions: one browser session does not automatically unlock another browser session.
- Automatic lock after 15 minutes.
- Manual lock is available from the main UI.

### Network and deployment hardening

- Gunicorn runs the Flask application under systemd.
- Stash listens only on `127.0.0.1:5000`.
- Tailscale Serve terminates/provides HTTPS access and proxies to the local application.
- UFW is enabled with incoming traffic denied by default.
- The Tailscale interface is allowed through UFW so Stash remains reachable through the Tailscale network.
- Port 5000 is **not** directly exposed.
- SSH was checked during hardening and was inactive on the host at that time.

## Runtime files

The deployed application uses files such as:

```text
~/stash/
├── app.py
├── stash.db
├── stash_config.json
├── stash_session_secret
└── venv/
```

The database, configuration, session secret, virtual environment, and backups are deployment state and must not be committed to this public repository. See `docs/SECURITY.md` and `.gitignore`.

## Installation / environment

Create the application directory and virtual environment:

```bash
mkdir -p ~/stash
cd ~/stash
python3 -m venv venv
source venv/bin/activate
```

Install the application dependencies used by the deployed version:

```bash
pip install flask cryptography gunicorn
```

The production application is run by systemd/Gunicorn rather than Flask's development server.

## Basic operation

Check the service:

```bash
sudo systemctl status stash.service
sudo systemctl is-active stash.service
```

Restart after application changes:

```bash
sudo systemctl restart stash.service
```

Verify localhost binding:

```bash
sudo ss -lntp | grep ':5000'
```

Expected binding:

```text
127.0.0.1:5000
```

Check Tailscale Serve:

```bash
tailscale serve status
```

Check firewall:

```bash
sudo ufw status verbose
```

## Tailscale access

Tailscale Serve is configured so the HTTPS Tailscale hostname proxies to:

```text
https://<your-tailscale-hostname>
        ↓
http://127.0.0.1:5000
```

The actual personal Tailscale hostname is intentionally not recorded in this public repository.

## UFW hardening

The deployed firewall configuration uses a deny-by-default incoming policy and permits traffic on the Tailscale interface.

Inspect it with:

```bash
sudo ufw status verbose
```

The important properties are:

- Incoming: deny by default.
- Outgoing: allow by default.
- Tailscale interface: allowed.
- Port 5000: **not** exposed directly.

## Backup and recovery

A final backup was created outside the Git repository under:

```text
~/stash-backups/
```

The important application state copied into the final backup was:

```text
app.py
stash.db
stash_config.json
stash_session_secret
```

A compressed archive was created, followed by a password-protected GPG copy using AES-256.

The final encrypted backup filename was:

```text
stash-final-backup.tar.gz.gpg
```

The GPG password is separate from the application's master password and is never stored in this repository.

See `docs/BACKUPS.md` for the complete backup and recovery procedure.

## Security notes

Stash is a personal self-hosted application. It is not intended to replace a mature, professionally audited password manager for high-risk secrets or multi-user deployments.

Operational rules:

1. Never commit `stash.db`, `stash_config.json`, `stash_session_secret`, passwords, or backup files to Git.
2. Never put the Stash master password or GPG backup password in documentation.
3. Keep the GPG backup password separately from the encrypted backup.
4. Keep the application bound to localhost when using Tailscale Serve.
5. Keep the host firewall enabled.
6. Back up the database and configuration together; the salt/configuration and session secret are part of the recovery state.
7. Test a recovery procedure periodically rather than assuming a backup works.

## Project status

The deployed Stash setup has been completed and tested for normal login/use, mobile access, folder collapse/expand, edit/delete controls, 15-minute automatic locking, per-browser login sessions, localhost-only binding, Tailscale HTTPS access, UFW protection, and encrypted backup creation/verification.

## Documentation

- `docs/SETUP.md` — step-by-step deployment and configuration history.
- `docs/SECURITY.md` — security model, secrets, network exposure, and operational precautions.
- `docs/BACKUPS.md` — backup, encryption, verification, and recovery procedures.
