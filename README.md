# Mortgage Calculator Web App

Flask wrapper around the existing mortgage calculator with per-user accounts and PostgreSQL-backed saved mixes.

## Local run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Local development uses SQLite automatically. Set `SECRET_KEY` to a long random value outside local testing.

## Deploy to Render

1. Push this folder's contents to a new GitHub repository (the `app.py`, `requirements.txt`, `templates/` folder, and `render.yaml` must be at repository root).
2. In Render, choose **New + → Blueprint**, connect the repository, and approve the resources in `render.yaml`.
3. The Blueprint creates the Flask web service and a PostgreSQL database. The included database plan is a paid persistent plan; check Render's current pricing before creating it.
4. Wait for deployment, then open the generated `onrender.com` URL and register an account.

The app stores password hashes (never plaintext passwords) and isolates each user's saved mixes by user ID. It uses a session cookie and CSRF token for state-changing requests.

## Notes

- The first logged-in user can import old mixes from this browser's previous localStorage automatically, if the new account has no saved mixes yet.
- For a public production launch, add email verification, password reset, rate limiting, backups, and monitoring before inviting users broadly.
