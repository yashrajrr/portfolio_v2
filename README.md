# Yashraj Rathor — Portfolio

A handcrafted portfolio for **Yashraj Rathor**, an IT undergraduate and aspiring data engineer.

## Features

- Editorial, responsive design with light and dark themes
- Motion-rich project storytelling and project filters
- Detailed experience, education, skills, credentials, and résumé
- Password-protected admin studio
- Draft/publish workflow and version history
- Customizable content, colors, typography, portrait, and résumé
- Contact form with a private admin inbox
- Durable private storage on Vercel Blob

## Stack

- React, TypeScript, Vite
- Motion, Radix UI, Lucide
- Flask, Pydantic
- Vercel and Vercel Blob

## Local development

```bash
npm install
npm run build
python -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/gunicorn --bind 127.0.0.1:8080 server:app
```

Without `BLOB_READ_WRITE_TOKEN`, the backend uses local SQLite and files under `data/`. On Vercel, private Blob storage is configured through environment variables.

## Password recovery

If the admin password is forgotten, temporarily add a strong random value as the
`ADMIN_RESET_TOKEN` environment variable in Vercel, then send one request to
`POST /api/auth/reset`:

```json
{
  "token": "the-value-configured-in-vercel",
  "email": "your-admin-email@example.com",
  "password": "your-new-password"
}
```

Include the `X-CSRF-Protection: 1` header. After the request succeeds, remove
`ADMIN_RESET_TOKEN` from Vercel and redeploy. The reset preserves portfolio
content, media, messages, and history.