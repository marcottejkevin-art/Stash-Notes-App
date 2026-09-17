# Stash Backup and Recovery

This document records the final backup procedure used for the deployed Stash instance and provides a repeatable recovery procedure.

## What must be backed up

A complete application-state backup includes:

```text
app.py
stash.db
stash_config.json
stash_session_secret
```

The database alone is not enough. The configuration contains the salt and password-verification material used by the application, and the session secret is part of the deployed application state.

## Backup location

The host backup directory used during setup is:

```text
~/stash-backups/
```

The final files were placed under:

```text
~/stash-backups/final/
```

## Create the final-state copy

From the application directory:

```bash
cd ~/stash
mkdir -p ~/stash-backups/final
cp app.py ~/stash-backups/final/
cp stash.db ~/stash-backups/final/
cp stash_config.json ~/stash-backups/final/
cp stash_session_secret ~/stash-backups/final/
```

Verify:

```bash
ls -lh ~/stash-backups/final
```

## Create a compressed archive

```bash
cd ~/stash-backups
tar -czf stash-final-backup.tar.gz final/
```

Verify:

```bash
ls -lh ~/stash-backups/stash-final-backup.tar.gz
```

This `.tar.gz` file is **not encrypted**. Treat it as sensitive and do not upload it to an untrusted location.

## Create the encrypted backup

The final encrypted backup was created with GPG using AES-256:

```bash
gpg --symmetric --cipher-algo AES256 ~/stash-backups/stash-final-backup.tar.gz
```

GPG prompts for a passphrase. Do not put the passphrase in the command line, source code, or repository documentation.

The resulting file is:

```text
~/stash-backups/stash-final-backup.tar.gz.gpg
```

Verify it exists:

```bash
ls -lh ~/stash-backups/stash-final-backup.tar.gz.gpg
```

The final encrypted backup was verified to exist successfully.

## Preferred future one-command archive + encryption

For future backups, the archive can be piped directly into GPG so the intermediate unencrypted archive does not need to be kept:

```bash
tar -czf - -C ~/stash-backups final | gpg --symmetric --cipher-algo AES256 -o ~/stash-backups/stash-final-backup.tar.gz.gpg
```

Verify:

```bash
ls -lh ~/stash-backups/stash-final-backup.tar.gz.gpg
```

## Restore procedure

### 1. Decrypt the backup

Use a protected local directory and decrypt the GPG file:

```bash
mkdir -p ~/stash-restore
gpg --decrypt ~/stash-backups/stash-final-backup.tar.gz.gpg > ~/stash-restore/stash-final-backup.tar.gz
```

### 2. Inspect before extracting

```bash
tar -tzf ~/stash-restore/stash-final-backup.tar.gz
```

Confirm the expected files are present before restoring anything.

### 3. Extract

```bash
mkdir -p ~/stash-restore/final
tar -xzf ~/stash-restore/stash-final-backup.tar.gz -C ~/stash-restore
```

### 4. Restore application state

Only after confirming the backup is the intended one, copy the required files into the Stash directory. Stop the service first:

```bash
sudo systemctl stop stash.service
```

Then restore the files from the extracted backup, for example:

```bash
cp ~/stash-restore/final/app.py ~/stash/
cp ~/stash-restore/final/stash.db ~/stash/
cp ~/stash-restore/final/stash_config.json ~/stash/
cp ~/stash-restore/final/stash_session_secret ~/stash/
```

Restart and verify:

```bash
sudo systemctl start stash.service
sudo systemctl is-active stash.service
```

Then verify the local binding:

```bash
sudo ss -lntp | grep ':5000'
```

## Protecting backup files

The backup contains sensitive deployment state even though the entry values in the database are encrypted. The configuration and session secret still require protection.

Recommended practice:

- Keep the GPG-encrypted backup as the portable copy.
- Store the GPG passphrase separately from the backup.
- Do not commit either backup archive to Git.
- Do not put the GPG passphrase in GitHub Issues, pull requests, source code, or documentation.
- Keep at least one backup in a location that is independent of the Stash host.
- Periodically verify that the backup can be decrypted and inspected.

## What is intentionally not backed up to GitHub

The GitHub repository documents the process but does not contain:

- `stash.db`
- `stash_config.json`
- `stash_session_secret`
- the Stash master password
- the GPG backup passphrase
- live backup archives
- personal Tailscale credentials

The repository `.gitignore` is configured to help prevent accidental commits of these files.
