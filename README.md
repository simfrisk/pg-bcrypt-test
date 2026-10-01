# pg-bcrypt-test

Test of moving Supabase users to OSC with their original passwords and no auth server.
Users live in an OSC PostgreSQL database; the app verifies bcrypt hashes with bcryptjs.

- `GET /` sign-in form
- `POST /signin` returns SIGN-IN OK or WRONG CREDENTIALS (same message for unknown email and wrong password)

Config comes only from the environment variable `DATABASE_URL` (OSC parameter store, encrypted secret).
The one-off import and DB probe routes used during setup were removed in a later commit.
