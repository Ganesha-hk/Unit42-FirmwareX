# Dedicated-server deployment

This guide describes a single Linux host for a trusted internal team. The local Docker workflow has been exercised, but an independently reproduced production installation and a live HTTPS deployment have not been verified. The application has a shared workspace, no roles or account-recovery UI, and one dispatcher. Decide whether those limits fit your use before deploying.

## 1. Prepare the host

Use a dedicated Linux x86-64 host with Docker Engine/Compose, Python 3, Git, persistent disk and a normal Docker-enabled user. Protect Docker access as host-level administrative access. Application Python remains containerized.

Clone the repository and run `sh scripts/start.sh` as described in the root README. Confirm the database migration completes, `/health` responds, an employee can register/log in, and a permitted image produces a stored assessment. Do not expose the site publicly while using the default HTTP setup.

The control image, extraction/QEMU/pipeline image tags and dependency lock files are versioned together. Keep them together during upgrades. Fixed tags are reused locally, so rebuilding does not by itself recreate running containers.

## 2. Configure a domain and HTTPS

Use a host-installed reverse proxy such as Nginx. Obtain a valid certificate for your domain using your organization's normal certificate process. `infra/nginx.conf.example` is a configuration template, not a certificate installer.

Replace its example hostname and certificate paths. Keep the API upstream at `127.0.0.1:8000` unless you have changed `FWX_HTTP_PORT`. The example preserves Host, supplies the HTTPS scheme, overwrites the incoming forwarded address, allows the upload size and redirects HTTP to HTTPS. It assumes one edge proxy; adapt forwarding deliberately if another proxy exists.

Validate the installed configuration with `sudo nginx -t`, then reload Nginx using your host's service manager. Do not publish PostgreSQL, Redis, the Docker socket or API port 8000 through the firewall. Expose only the intended HTTPS endpoint (and port 80 if redirect/certificate issuance needs it).

## 3. Trust only the actual proxy peer

The API checks request Origin for registration, login, logout and authenticated writes. The external scheme and hostname must reach Uvicorn correctly. Otherwise legitimate login requests can return 403.

Find the actual source address that the API sees for requests coming from your host proxy. Depending on Docker's networking, this may be a bridge gateway rather than `127.0.0.1`. Inspect the API container networks and access logs; do not blindly trust every address on a network. Proxy forwarding also affects per-address login rate limits.

Set the exact trusted peer in the private `.env`:

```dotenv
FWX_TRUSTED_PROXY_IPS=the-exact-proxy-peer-address
```

Replace that placeholder before running Compose. Do not use `*` on an endpoint reachable by untrusted clients. The production override turns on secure cookies and passes this trusted-peer setting to Uvicorn:

```sh
docker compose -f compose.yaml -f compose.production.yaml config --quiet
docker compose -f compose.yaml -f compose.production.yaml up -d
```

Use the HTTPS domain for browser login. Secure session cookies will not work over ordinary HTTP. Keep the same Compose project name and storage configuration; changing project names creates different volumes.

The override adds restart policies and log rotation for the API/worker/scheduler. It intentionally does not restart the one-shot migration endlessly. Restarts do not provide high availability or guarantee database readiness after every host failure.

## 4. Verify before allowing other users

- Register a test employee using the correct company code; verify a wrong code is rejected.
- Log in, refresh the page, log out, and verify the old session no longer grants access.
- Confirm POST requests work over HTTPS with your real domain and arbitrary origins fail.
- Verify that secure cookies are set, the raw API/database/queue ports are not publicly reachable, and forwarded client addresses are accurate.
- Upload a permitted image and inspect saved stage results, limits and report exports.
- Restart the stack without deleting volumes and confirm the assessment remains.
- Test your backup restore on a separate host or isolated instance.

These are operator acceptance steps, not results already claimed for your server. `/health` alone is insufficient.

## 5. Storage and backup

Retain all of the following together: PostgreSQL data, Redis queue state when needed for recovery, the `FWX_HOST_STORAGE` job/input directory, the private environment configuration, the matching application revision and image identifiers. Protect backups because they contain account hashes, source images and application credentials.

For a consistent maintenance backup, restrict new uploads, let active work finish, and stop the API, dispatcher and scheduler. Keep PostgreSQL running long enough to create a logical dump. For example, from the project root (using the same environment/Compose options as your instance):

```sh
umask 077
mkdir -p backups
docker compose stop api dispatcher scheduler
docker compose exec -T postgres pg_dump -U postgres -d firmwarex -Fc > backups/firmwarex.dump
```

Use your backup tool to snapshot/archive the actual host storage directory and private configuration, and back up Redis consistently if queued work must be recovered. Restart services with the same two Compose files afterward. The dump command alone is not a full backup. Never add backups to Git, and do not restore over a live installation as a test.

## 6. Upgrade and rollback

1. Announce maintenance; prevent uploads and allow active jobs to finish.
2. Back up the database, storage and configuration; record the current commit and image IDs.
3. Fetch the intended revision. Read the schema migrations before applying it.
4. Rebuild images in the order in `scripts/start.sh`, without launching an intermediate HTTP deployment.
5. Run the two-file production Compose command to apply migrations and recreate services.
6. Repeat authentication, upload, report and persistence checks.

Image rollback is not enough if a migration changed the schema. Restore a tested database/storage backup or use a reviewed compatible migration plan. Do not use `docker compose down -v` during upgrades.

## 7. Troubleshooting

| Symptom | Check |
| --- | --- |
| 403 during HTTPS login | Origin, Host, forwarded scheme and the exact trusted proxy peer |
| Login rate limited | Wait five minutes; check client-address forwarding and failed attempts |
| Registration unavailable | A company code of at least 32 characters must be configured in the API |
| Service fails to start | Migration logs, database health and mounted-directory ownership |
| Job stays queued | Redis, dispatcher, scheduler, Docker socket access and pipeline image availability |
| Emulation/symbolic incomplete | Stage reasons: missing runtime models/libraries, unsupported profiles or actual budgets |
| Report missing after restart | Same Compose project, retained volumes and unchanged storage path |
| First build fails | Access to pinned image/package sources, disk capacity and Docker build logs |

Do not paste resolved Compose configuration or private environment values into public issues.

## References

- [Docker: use Compose in production](https://docs.docker.com/compose/how-tos/production/)
- [Uvicorn: deployment and trusted proxy headers](https://uvicorn.dev/deployment/)
- [FastAPI: HTTPS and TLS termination](https://fastapi.tiangolo.com/deployment/https/)
