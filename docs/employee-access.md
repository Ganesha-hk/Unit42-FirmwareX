# Employee access

Implemented 2026-11-10 as an additional user-requested feature. Existing firmware assessments are preserved. The updated local instance runs at http://127.0.0.1:8001/.

## First account

1. Open the website and select **Create an account**.
2. Enter your company employee ID, a password (12–128 characters), confirmation, and company registration code.
3. After registration, log in using only your employee ID and password.

The company administrator obtains `FWX_COMPANY_REGISTRATION_CODE` from private `work/submission-instance/.env` for port 8001 and shares it privately with intended employees. Never include it in a recording or submission. The default port-8000 configuration is a separate `.env` with its own code. The code is shared for onboarding, not a password, not a one-time invitation, and not needed during login. Rotating it affects future registrations only. Employee IDs are case-insensitive and stored uppercase.

Existing configurations can be initialized once with `python3 scripts/configure-employee-access.py --env-file PATH_TO_ENV`. New bootstrap configurations include a random code. Missing or short codes disable registration. Recreate the API after changing configuration.

## Implementation and limits

- Additive migration `0003` creates employee and session tables. It does not change firmware records.
- Passwords use salted PBKDF2-HMAC-SHA256 with 600,000 iterations. Session tokens are random; only their SHA-256 hashes are stored.
- Eight-hour, HttpOnly, SameSite=Strict cookies; logout revokes the server session. POST requests using cookies require matching Origin.
- Redis enforces per-address and per-employee attempt limits; unavailable Redis denies authentication attempts.
- Authentication validation errors do not echo passwords/codes. API responses use no-store caching.
- All employees access the existing shared company workspace. There are no administrator roles, HR employee-directory verification, password recovery, or account-management screens yet. Anyone possessing the shared code can register an unused employee ID.
- Private Bearer-token automation remains supported; the browser no longer asks employees for the API token.
- Current deployment remains loopback-only HTTP. A future HTTPS deployment must set `FWX_SESSION_COOKIE_SECURE=true` and configure its trusted proxy/origin handling appropriately.

## Verification

`evidence/employee-access-2026-11-10/`: 170 unit tests passed, including 11 employee-authentication tests; actual browser/PostgreSQL registration, rejected code, login, refresh, existing real report access, logout and mobile layout passed. Screenshots show desktop login/registration and mobile login. One test-only QA account with an unrecoverable random password remains as recorded in `browser.json`; it is logged out. The initial full-suite run omitted fixture mounts and failed 14 fixture-dependent tests; its log is retained, and the correctly configured rerun passed all 170.

The firmware submission's historical 159-test count remains evidence of that earlier run. These extra authentication tests do not close unrelated PRD obligations. The natural-paced firmware-upload recording is a separate pending task.
