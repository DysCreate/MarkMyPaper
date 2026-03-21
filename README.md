# MarkMyPaper

MarkMyPaper is a Flask-based web application for automated grading of handwritten or typed answer submissions. It combines OCR (TrOCR), PDF/image text extraction, and fuzzy text matching to compare student responses against model answers.

## Features

- User authentication (register, login, profile, logout)
- JWT-protected API routes
- Password reset token flow
- Upload support for `PDF`, `JPG`, `JPEG`, and `PNG`
- OCR/text extraction pipeline:
    - TrOCR for images
    - PyPDF2 for PDFs
- Weighted answer grading using similarity scoring
- Result breakdown per model answer + total score

## Tech Stack

- Python 3
- Flask, Flask-SQLAlchemy, Flask-CORS
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
│   ├── dashboard.html
│   ├── home.html
│   ├── login.html
│   ├── trial.html
│   └── upload.html
└── static/
        ├── home.css
        ├── login.css
        └── styles.css
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

The app starts in debug mode at `http://127.0.0.1:5000`.

> On first run, Hugging Face model files for TrOCR are downloaded, so startup may take longer.

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
    - Returns extracted text, per-answer similarity/score, and total score

## Notes

- User data is stored in local SQLite (`instance/users.db`).
- `SECRET_KEY` is currently hardcoded in `app.py`; for production use, move it to an environment variable.
- This project is set up for local development and experimentation.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

