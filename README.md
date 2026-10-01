# pg-bcrypt-test

Test of moving Supabase users to OSC with their original passwords and no auth server.
Users live in an OSC PostgreSQL database; the app verifies bcrypt hashes with bcryptjs.

- `GET /` sign-in form
- `POST /signin` returns SIGN-IN OK or WRONG CREDENTIALS (same message for unknown email and wrong password)

Config comes only from environment variables (OSC parameter store): `DATABASE_URL`, and for the
one-off import `ADMIN_TOKEN` plus `ADMIN_ENABLED=true`. With `ADMIN_ENABLED` unset there are no admin routes.
