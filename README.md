# Flask Task Manager

Simple Task Manager app with:
- Registration (email + username + password)
- Login (username + password)
- JWT cookie sessions (20 minute expiry)
- Forgot / Reset password (token printed to console in dev)
- SQLite for storage
- GitHub Actions CI & Dockerfile included

## Quick start (local)

1. Create virtualenv and activate:
```bash
python -m venv venv
# macOS/Linux:
source venv/bin/activate
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
