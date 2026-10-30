# idvault

Backup and restore for directory users and groups (the kind of data that lives in Active Directory or Entra ID), written in Go with no dependencies outside the standard library.

It takes snapshots of a directory, flags snapshots that look like an attack, and restores either everything or a few users and groups. Restores that touch privileged groups like Domain Admins need two security officers to approve them. There's a small web console and a JSON API.

The directory here is an in-memory stand-in loaded with a sample company (harbourline.local, 60 accounts). Connecting to a real directory is the main thing missing; see the end of this file.

![Snapshot flagged by the detector](docs/04-snapshots-flagged.png)
![Restore waiting for two approvals](docs/06-restore-waiting.png)

## Running it

Needs Go 1.22 or newer.

```
make dev     # console at http://localhost:8080 with sample accounts, sign in from the picker
make demo    # runs an attack and recovery in the terminal against the real API
make test
```

`make dev` uses fixed tokens (`dev-<name>`) so you can switch accounts quickly. Don't use it on a network. `make run` starts the server normally; it prints a random token for each account on first start and only stores their hashes.

To try the main flow in the console:

1. Sign in as **hlindqvist** (helpdesk) and run the simulated attack on the Directory page.
2. Sign in as **amehta** and take a snapshot. It gets flagged. Try deleting an older snapshot; the lock refuses it.
3. Sign in as **kasante**, preview a full restore from the last clean snapshot with "Match the snapshot exactly", and request approval.
4. Approve as **gsantos** and **rmalhotra**.
5. Back as **kasante**, preview again and run the restore.
6. Sign in as **taziz** and check the audit log chain.

## How it works

**Storage.** Each user and group is saved as a JSON file named by its SHA-256 hash. A snapshot is a manifest listing those hashes plus the hash of the previous manifest. Records that didn't change since the last snapshot aren't written again, so a snapshot after one edit stores one new file. Every read re-hashes the file, so a changed or corrupted backup is caught before it's restored.

**Locks.** Each policy has a lock period. Until it passes, the code refuses to delete the snapshot, for every role. The newest snapshot is never pruned.

**Detection.** Each snapshot is compared with the one before it. Deleting or disabling a large share of users in one interval, deleting groups, or adding someone to a privileged group marks it flagged. Once a snapshot is flagged, later ones are compared with the last clean snapshot instead, otherwise a quiet hour after an attack would look clean. A security officer can overrule a verdict, with a reason that goes in the audit log.

**Restore.** A restore is planned first and you see every change before anything runs. "Bring back what's missing" never deletes. "Match the snapshot exactly" also removes what was added since, like an attacker's account. Restoring one user also restores their group memberships, and the preview warns you if one of their groups was deleted too. Before a restore runs, the current state is saved as a snapshot so it can be undone.

**Approvals.** The approval is tied to a hash of the plan. If the directory changes between approval and running, the plan is different, the hash doesn't match, and the restore is refused. Approvals are single use, expire after 30 minutes, and can't be given by the person who asked.

**Roles.** The helpdesk role that manages users has no access to backups at all, since that's the kind of account that gets phished. Nobody can both run and approve a restore.

**Audit log.** Every request is logged, including refused ones. Each line includes the hash of the line before, so editing or deleting a line breaks the chain.

## Layout

```
cmd/idvault          serve and demo commands
internal/directory   users, groups, diff, sample data
internal/store       content-addressed files, manifests, locks
internal/snapshot    taking and loading snapshots, finding the last clean one
internal/anomaly     detection rules
internal/restore     planning and running restores
internal/rbac        roles and tokens
internal/approval    two-person approval
internal/audit       hash-chained log
internal/scheduler   runs policies on a timer
internal/api         HTTP API and the web console (internal/api/ui)
```

