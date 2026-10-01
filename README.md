# MarkMyPaper

MarkMyPaper is a Flask-based web application for automated grading of handwritten or typed answer submissions. It combines OCR (TrOCR), PDF/image text extraction, and fuzzy text matching to compare student responses against model answers.

## Features

- User authentication (register, login, profile, logout)
- JWT-protected API routes
- Password reset token flow
- Upload support for `PDF`, `JPG`, `JPEG`, and `PNG`
- OCR/text extraction pipeline:
    - TrOCR for images
    - PyPDF2 for text-based PDFs
    - OCR fallback for scanned PDF pages
- Weighted answer grading using similarity scoring
- Result breakdown per model answer + total score

## Tech Stack

- Python 3
- Flask, Flask-SQLAlchemy, Flask-CORS, Flask-Limiter
- Transformers (`microsoft/trocr-base-handwritten`)
- PyTorch
- Pillow, PyPDF2
- TheFuzz (`token_sort_ratio`) for grading similarity
- SQLite (via SQLAlchemy)

## Project Structure

```text
MarkMyPaper/
├── app.py
├── requirements.txt
├── templates/
│   ├── home.html
│   ├── start.html
│   ├── login.html
│   ├── upload.html
│   ├── dashboard.html
│   ├── terms.html
│   └── privacy.html
└── static/
        └── site.css
```

## Getting Started

### 1) Clone the repository

```bash
git clone https://github.com/DysCreate/MarkMyPaper.git
cd MarkMyPaper
```

### 2) Create and activate a virtual environment (recommended)

```bash
python -m venv .venv
```

Windows (PowerShell):

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

### 3) Install dependencies

```bash
pip install -r requirements.txt
```

### 4) Run the application

```bash
python app.py
```

The app starts at `http://127.0.0.1:5000` (debug mode is off by default).

### Configuration

Settings are read from environment variables. Copy `.env.example` to `.env`
and fill it in, or export the variables directly. The one you must set for a
real deployment is:

- `SECRET_KEY` — signs JWTs. Generate one with
  `python -c "import secrets; print(secrets.token_hex(32))"`. If it is unset the
  app generates a temporary key and logs users out on restart.

Optional: `FLASK_DEBUG`, `DATABASE_URL`, `HOST`/`PORT`, `MAX_UPLOAD_MB`,
`CORS_ORIGINS`, `RATELIMIT_STORAGE_URI`, `APP_BASE_URL`, `FORCE_HTTPS`, and the
`SMTP_*` variables used to email password-reset links. See `.env.example` for
the full list. Password-reset email is only sent when `SMTP_HOST` is set; the
API never returns the reset token to the caller.

> The TrOCR model is loaded lazily: on your first grading run, the Hugging Face model files are downloaded, so that first OCR request takes longer. The app and its pages boot without the model.

## API Overview

### Auth

- `POST /api/register`
- `POST /api/login`
- `GET /api/user` (requires `Authorization: Bearer <token>`)
- `POST /api/logout` (requires token)
- `POST /api/reset-password-request`
- `POST /api/reset-password`

### Grading

- `POST /upload`
    - Form-data fields:
        - `file` (PDF/image)
        - `answers` (repeatable)
        - `weights` (repeatable)
        - `force_ocr` (optional, `true`/`false`; defaults to `false`)
    - Returns extracted text, per-answer similarity/score, total score, page count, and page-level extraction details

## Testing

```bash
python -m unittest discover -s tests -v
```

## Notes

- User data is stored in local SQLite (`instance/users.db`); the file is
gitignored and should never be committed (it contains password hashes).
- `SECRET_KEY` is read from the environment. If the one that was previously
nhardcoded was ever used in a deployment, rotate it.
- The app serves a custom 404 page for unknown routes and returns JSON
  `{"error": "Not found"}` for unknown `/api/*` routes.
- Security headers (CSP with per-request nonces, HSTS, `X-Content-Type-Options`,
  `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`) are set on every
  response, and auth endpoints are rate limited.
- This project is set up for local development and experimentation.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

