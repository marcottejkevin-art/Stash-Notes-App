# Stash Security Notes

Stash stores information that may include real account credentials. The deployed configuration therefore treats the application as sensitive even though the repository contains only source/documentation.

## Threat model

The current design is intended for a personal, self-hosted deployment on a trusted Ubuntu machine. It is designed to reduce the risk of accidental exposure and unauthorized access through the network or an unattended browser.

It is **not** presented as a professionally audited password manager or as a multi-user security system.

## Data protection

Stash encrypts the following entry fields before storing them in SQLite:

- name
- username
- password
- category
- notes

The encryption mechanism uses Fernet authenticated symmetric encryption.

The Fernet key is derived from the user's master password with PBKDF2-HMAC-SHA256 using 600,000 iterations and a random 16-byte salt.

The master password itself is not stored.

`stash_config.json` contains the salt and password-verification material required by the application. Treat it as sensitive deployment state.

## Authentication

The application requires a master password to unlock Stash.

The minimum master-password length is 12 characters.

Per-browser login sessions were implemented so an authenticated browser session is not automatically reused by a different browser/private session.

## Locking

Stash has a 15-minute automatic lock and a manual Lock control.

The automatic locking behavior was tested during deployment.

## Session secret

`stash_session_secret` is used as sensitive session state. It must be protected like any other application secret and included in a complete private backup, but never committed to the public repository.

## Network exposure

The production application listens only on:

```text
127.0.0.1:5000
```

This is an important part of the deployment design. Port 5000 should not be opened directly to the LAN or Internet.

Tailscale Serve provides the HTTPS access path and proxies requests to the local application.

The personal Tailscale hostname is intentionally omitted from this public documentation.

## Firewall

UFW is enabled with incoming traffic denied by default. The Tailscale interface is allowed so Tailscale clients can reach the HTTPS service.

Check the current state with:

```bash
sudo ufw status verbose
```

Do not add a public `5000/tcp` rule just to make Tailscale work.

## Browser hygiene

Because Stash can display decrypted values after login:

- lock Stash when finished if the device is shared or unattended
- avoid leaving an unlocked Stash tab open on an untrusted device
- use the automatic 15-minute lock as a safety net rather than as a substitute for manual locking
- keep the phone/browser itself protected with its normal device security

## Repository hygiene

The GitHub repository is public, so live deployment state must remain outside it.

The repository `.gitignore` excludes:

```text
stash.db
stash_config.json
stash_session_secret
venv/
.env*
backup/archive files
```

Before committing any change, check that no sensitive files are staged.

Useful local checks include:

```bash
git status
```

and:

```bash
git diff --cached
```

Never paste passwords, private keys, GPG passphrases, Tailscale auth keys, or other secrets into source code or documentation.

## Backup security

The final backup contains both the encrypted database and sensitive configuration/session files. The final archive was protected with GPG symmetric encryption using AES-256.

The GPG passphrase is not stored with the backup and is not stored in GitHub.

A backup is only useful if both the encrypted file and its passphrase can be recovered. Store the passphrase separately and securely.

## Recovery security

When restoring a backup:

1. Work on a trusted host.
2. Keep the encrypted backup intact until recovery is confirmed.
3. Decrypt to a protected local location.
4. Restore only the expected files.
5. Set appropriate filesystem permissions on sensitive files.
6. Start Stash and verify login/data access.
7. Verify Tailscale and UFW configuration before making the service reachable again.
8. Create a fresh encrypted backup after successful recovery.

## Security limitations

The current implementation is intentionally small. It does not claim to provide all of the protections of a mature password manager, enterprise secret manager, hardware-backed credential store, or externally audited security product.

If Stash evolves into a multi-user or Internet-facing service, its threat model should be revisited before expanding network exposure.
