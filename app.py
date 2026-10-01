"""MarkMyPaper backend.

A small self-hosted Flask service that reads answer sheets with OCR and grades
them by measured text similarity.

Security-hardened build. Configuration is read from the environment; see
``.env.example`` and the README for the variables that must be set in
production.
"""
import datetime
import gzip
import io
import json
import logging
import math
import os
import re
import secrets
import smtplib
from email.message import EmailMessage
from functools import wraps
from urllib.parse import quote

import jwt
from flask import (
    Flask,
    abort,
    g,
    jsonify,
    render_template,
    request,
    send_from_directory,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import PyPDF2
import pypdfium2 as pdfium
from thefuzz import fuzz

# Optional: load a local .env so developers do not have to export every
# variable by hand. Absent in production, which is fine.
try:  # pragma: no cover - optional dependency
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def _env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _utcnow():
    """Naive UTC timestamp, matching the column types already in the schema."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


APP_NAME = "MarkMyPaper"
DEBUG = _env_bool("FLASK_DEBUG", False)

app = Flask(__name__)

# --- Secret key ------------------------------------------------------------
# A hardcoded key here let anyone who read the public source forge JWTs. The
# key must now come from the environment. As a safe fallback for local runs we
# generate an ephemeral key, which means tokens do not survive a restart.
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)
    logging.getLogger(__name__).warning(
        "SECRET_KEY is not set; using an ephemeral key. Tokens will be "
        "invalidated on restart. Set SECRET_KEY in the environment for any "
        "deployment."
    )
app.config["SECRET_KEY"] = _secret
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///users.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_UPLOAD_MB", "20")) * 1024 * 1024
app.config["PROPAGATE_EXCEPTIONS"] = False

db = SQLAlchemy(app)

# --- Rate limiting ---------------------------------------------------------
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# --- CORS ------------------------------------------------------------------
# Only the explicitly trusted origins are allowed to call the API cross-origin.
# With no allowlist configured the API is same-origin only (no CORS headers),
# which is what a self-hosted install wants.
_allowed_origins = [
    origin.strip()
    for origin in os.environ.get("CORS_ORIGINS", "").split(",")
    if origin.strip()
]
if _allowed_origins:
    CORS(app, resources={r"/api/*": {"origins": _allowed_origins}})


logging.basicConfig(level=logging.INFO)


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=_utcnow)


class GradingRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    page_count = db.Column(db.Integer, default=0)
    total_score = db.Column(db.Float, default=0)
    max_score = db.Column(db.Float, default=0)
    methods = db.Column(db.String(255), default="")
    extracted_text = db.Column(db.Text, default="")
    results = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=_utcnow, index=True)


# --------------------------------------------------------------------------- #
# Request helpers
# --------------------------------------------------------------------------- #
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LOWERCASE_HASH_METHODS = ("scrypt:", "pbkdf2:")


def _wants_json():
    return request.path.startswith("/api/") or (
        request.accept_mimetypes.best == "application/json"
    )


def _json_body():
    """Return a dict body or None. Never raises on malformed input."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _clean_str(value, max_len):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_len:
        return None
    return value


def _hash_password(password):
    """Hash with Werkzeug's current default (scrypt), which is salted and slow."""
    return generate_password_hash(password)


def _issue_token(user_id, purpose, lifetime):
    now = _utcnow()
    return jwt.encode(
        {
            "user_id": user_id,
            "purpose": purpose,
            "iat": now,
            "exp": now + lifetime,
            "jti": secrets.token_hex(8),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"message": "Authentication required"}), 401
        token = header[len("Bearer ") :].strip()
        try:
            data = jwt.decode(
                token,
                app.config["SECRET_KEY"],
                algorithms=["HS256"],
                options={"require": ["exp", "user_id", "purpose"]},
            )
            # A password-reset token must never be usable as a session token.
            if data.get("purpose") != "auth":
                raise jwt.InvalidTokenError("wrong token purpose")
            current_user = db.session.get(User, data["user_id"])
        except jwt.PyJWTError:
            return jsonify({"message": "Invalid or expired token"}), 401
        if current_user is None:
            return jsonify({"message": "Invalid or expired token"}), 401
        return f(current_user, *args, **kwargs)

    return decorated


# --------------------------------------------------------------------------- #
# Email (password reset delivery)
# --------------------------------------------------------------------------- #
def _send_email(to_addr, subject, body):
    """Send mail through SMTP. Returns False (never raises) if unconfigured."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        app.logger.warning("SMTP_HOST is not configured; email not sent.")
        return False
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    password = os.environ.get("SMTP_PASSWORD")
    sender = os.environ.get("SMTP_FROM") or user or "no-reply@localhost"
    use_tls = _env_bool("SMTP_USE_TLS", True)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_addr
    message.set_content(body)
    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(message)
        return True
    except Exception:
        app.logger.exception("Failed to send password-reset email")
        return False


# --------------------------------------------------------------------------- #
# Security headers, CSP and response optimisation
# --------------------------------------------------------------------------- #
@app.before_request
def _set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _inject_csp_nonce():
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


_COMPRESSIBLE = ("text/", "application/json", "application/javascript", "image/svg+xml")


@app.after_request
def _apply_headers(response):
    nonce = getattr(g, "csp_nonce", "")
    csp = (
        "default-src 'self'; "
        f"script-src 'nonce-{nonce}'; "
        # Inline style attributes are still used across the templates, so the
        # style directive cannot be fully strict yet. Scripts are nonce-only.
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )
    if request.is_secure or _env_bool("FORCE_HTTPS", False):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    # Caching: long-lived for static assets, no-store for everything dynamic so
    # authenticated/API responses are never cached by shared caches.
    if request.path.startswith("/static/"):
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers.setdefault("Cache-Control", "no-store")

    # Transparent gzip for text responses (avoids pulling in a compression dep).
    if (
        response.status_code == 200
        and not response.direct_passthrough
        and "gzip" in request.headers.get("Accept-Encoding", "")
        and response.mimetype.startswith(_COMPRESSIBLE)
    ):
        data = response.get_data()
        if len(data) >= 500:
            compressed = gzip.compress(data, compresslevel=6)
            response.set_data(compressed)
            response.headers["Content-Encoding"] = "gzip"
            response.headers["Content-Length"] = str(len(compressed))
            response.headers.add("Vary", "Accept-Encoding")
    return response


# --------------------------------------------------------------------------- #
# Error handlers (no internal details, JSON for the API, page for the site)
# --------------------------------------------------------------------------- #
GENERIC_500_PAGE = (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
    "<title>Something went wrong / MarkMyPaper</title></head><body>"
    "<h1>Something went wrong</h1>"
    "<p>The server could not complete this request. Please try again.</p>"
    "<p><a href='/'>Back to home</a></p></body></html>"
)


@app.errorhandler(404)
def handle_not_found(_error):
    if _wants_json():
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404


@app.errorhandler(413)
def handle_too_large(_error):
    message = "Uploaded file is too large."
    if _wants_json():
        return jsonify({"error": message}), 413
    return message, 413


@app.errorhandler(Exception)
def handle_unexpected(error):
    if isinstance(error, HTTPException):
        return error
    app.logger.exception("Unhandled server error")
    if _wants_json():
        return jsonify({"error": "Internal server error"}), 500
    return GENERIC_500_PAGE, 500


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.route("/")
def serve_index():
    return render_template("home.html")


@app.route("/<path:path>")
def serve_file(path):
    # Only top-level template names are renderable; a path with sub-directories
    # or traversal segments is rejected outright.
    if path.endswith(".html"):
        name = os.path.basename(path)
        templates_dir = os.path.join(
            app.root_path, app.template_folder or "templates"
        )
        if name == path and os.path.isfile(os.path.join(templates_dir, name)):
            return render_template(name)
        abort(404)
    return send_from_directory("static", path)


# --------------------------------------------------------------------------- #
# Auth API
# --------------------------------------------------------------------------- #
@app.route("/api/register", methods=["POST"])
@limiter.limit("10 per hour")
def register():
    data = _json_body()
    if data is None:
        return jsonify({"message": "Invalid request body"}), 400

    name = _clean_str(data.get("name"), 100)
    email = _clean_str(data.get("email"), 120)
    password = data.get("password")

    if not name or not email or not isinstance(password, str):
        return jsonify({"message": "Missing or invalid required fields"}), 400
    if not EMAIL_RE.match(email):
        return jsonify({"message": "Invalid email address"}), 400
    if len(password) < 8 or len(password) > 200:
        return jsonify({"message": "Password must be 8 to 200 characters"}), 400

    email = email.lower()
    # Deliberately generic message so this endpoint cannot be used to
    # enumerate which emails are registered.
    if User.query.filter_by(email=email).first():
        return (
            jsonify(
                {
                    "message": "Registration could not be completed. If you "
                    "already have an account, log in or reset your password."
                }
            ),
            400,
        )

    new_user = User(name=name, email=email, password=_hash_password(password))
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to create user")
        return jsonify({"message": "Could not create the account"}), 500

    token = _issue_token(new_user.id, "auth", datetime.timedelta(days=1))
    return (
        jsonify(
            {
                "message": "Registration successful",
                "token": token,
                "user": {
                    "id": new_user.id,
                    "name": new_user.name,
                    "email": new_user.email,
                },
            }
        ),
        201,
    )


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per minute; 50 per hour")
def login():
    data = _json_body()
    if data is None:
        return jsonify({"message": "Invalid request body"}), 400

    email = _clean_str(data.get("email"), 120)
    password = data.get("password")
    if not email or not isinstance(password, str):
        return jsonify({"message": "Missing required fields"}), 400

    user = User.query.filter_by(email=email.lower()).first()
    if not user or not check_password_hash(user.password, password):
        # Same response for unknown email and wrong password: no enumeration.
        return jsonify({"message": "Invalid email or password"}), 401

    # Upgrade legacy/short hashes transparently on successful login.
    if not user.password.startswith(LOWERCASE_HASH_METHODS):
        try:
            user.password = _hash_password(password)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Failed to upgrade password hash")

    token = _issue_token(user.id, "auth", datetime.timedelta(days=1))
    return (
        jsonify(
            {
                "message": "Login successful",
                "token": token,
                "user": {"id": user.id, "name": user.name, "email": user.email},
            }
        ),
        200,
    )


@app.route("/api/user", methods=["GET"])
@token_required
@limiter.limit("120 per minute")
def get_user(current_user):
    return (
        jsonify(
            {
                "user": {
                    "id": current_user.id,
                    "name": current_user.name,
                    "email": current_user.email,
                }
            }
        ),
        200,
    )


@app.route("/api/logout", methods=["POST"])
@token_required
def logout(current_user):
    # Stateless JWTs cannot be revoked server-side without a denylist; the
    # client discards the token. Short expiry bounds the exposure.
    return jsonify({"message": "Logout successful"}), 200


@app.route("/api/reset-password-request", methods=["POST"])
@limiter.limit("5 per hour")
def reset_password_request():
    data = _json_body()
    if data is None:
        return jsonify({"message": "Invalid request body"}), 400

    email = _clean_str(data.get("email"), 120)
    if not email or not EMAIL_RE.match(email):
        return jsonify({"message": "Invalid email address"}), 400

    user = User.query.filter_by(email=email.lower()).first()
    if user:
        token = _issue_token(user.id, "password_reset", datetime.timedelta(hours=1))
        base = os.environ.get("APP_BASE_URL") or request.host_url.rstrip("/")
        link = "{}/reset.html?token={}".format(base, quote(token, safe=""))
        _send_email(
            user.email,
            "Reset your MarkMyPaper password",
            "Hello,\n\n"
            "Use the link below to reset your MarkMyPaper password. It expires "
            "in one hour. If you did not request this, you can ignore this "
            "message.\n\n" + link + "\n",
        )

    # Always the same response, whether or not the account exists.
    return (
        jsonify(
            {
                "message": "If that email is registered, password reset "
                "instructions have been sent."
            }
        ),
        200,
    )


@app.route("/api/reset-password", methods=["POST"])
@limiter.limit("10 per hour")
def reset_password():
    data = _json_body()
    if data is None:
        return jsonify({"message": "Invalid request body"}), 400

    token = data.get("token")
    new_password = data.get("new_password")
    if not isinstance(token, str) or not isinstance(new_password, str):
        return jsonify({"message": "Missing required fields"}), 400
    if len(new_password) < 8 or len(new_password) > 200:
        return jsonify({"message": "Password must be 8 to 200 characters"}), 400

    try:
        token_data = jwt.decode(
            token,
            app.config["SECRET_KEY"],
            algorithms=["HS256"],
            options={"require": ["exp", "user_id", "purpose"]},
        )
        if token_data.get("purpose") != "password_reset":
            raise jwt.InvalidTokenError("wrong token purpose")
        user = db.session.get(User, token_data["user_id"])
        if user is None:
            raise jwt.InvalidTokenError("unknown user")
    except jwt.PyJWTError:
        return jsonify({"message": "Invalid or expired reset token"}), 401

    user.password = _hash_password(new_password)
    db.session.commit()
    return jsonify({"message": "Password reset successful"}), 200


# --------------------------------------------------------------------------- #
# Grading / upload
# --------------------------------------------------------------------------- #
_ml_ready = False
_ml_error = None


def _load_ml():
    """Load the TrOCR model on first use so the app and its pages boot fast,
    and so the ML stack is required only when a sheet is actually graded."""
    global _ml_ready, _ml_error, _processor, _model
    if _ml_ready or _ml_error:
        return
    try:
        from transformers import VisionEncoderDecoderModel, TrOCRProcessor

        _processor = TrOCRProcessor.from_pretrained("microsoft/trocr-base-handwritten")
        _model = VisionEncoderDecoderModel.from_pretrained(
            "microsoft/trocr-base-handwritten"
        )
        _ml_ready = True
    except Exception as e:
        _ml_error = "The OCR model failed to load: {}".format(e)


def run_trocr(image):
    _load_ml()
    if not _ml_ready:
        raise RuntimeError(_ml_error or "The OCR model is not available")
    pixel_values = _processor(image, return_tensors="pt").pixel_values
    generated_ids = _model.generate(pixel_values)
    return _processor.batch_decode(generated_ids, skip_special_tokens=True)[0]


def extract_text(file_bytes, file_type, force_ocr=False):
    if file_type in ["jpg", "jpeg", "png"]:
        image = Image.open(io.BytesIO(file_bytes)).convert("RGB")
        extracted_text = run_trocr(image)
        page_details = [
            {"page_number": 1, "text": extracted_text, "method": "ocr"}
        ]
    elif file_type == "pdf":
        pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
        pdf_document = pdfium.PdfDocument(io.BytesIO(file_bytes))
        page_details = []

        for page_index, page in enumerate(pdf_reader.pages):
            page_number = page_index + 1
            page_text = ""
            extraction_method = "text"

            if not force_ocr:
                extracted_page_text = page.extract_text() or ""
                page_text = extracted_page_text.strip()

            if force_ocr or not page_text:
                rendered_page = (
                    pdf_document[page_index].render(scale=2).to_pil().convert("RGB")
                )
                page_text = run_trocr(rendered_page).strip()
                extraction_method = "ocr"

            page_details.append(
                {
                    "page_number": page_number,
                    "text": page_text,
                    "method": extraction_method,
                }
            )

        extracted_text = "\n\n".join(
            detail["text"] for detail in page_details if detail["text"]
        )
    else:
        raise ValueError("Unsupported file type")

    return {
        "extracted_text": extracted_text,
        "page_details": page_details,
        "page_count": len(page_details),
    }


def grade_answer(extracted_text, model_answers, weights):
    """
    Grades the extracted text based on sentence similarity.
    Returns detailed scoring information.
    """
    results = []
    total_score = 0
    text_lower = extracted_text.lower()

    for model_answer, weight in zip(model_answers, weights):
        model_answer_lower = model_answer.lower()

        # Use token sort ratio for better sentence comparison
        similarity_score = fuzz.token_sort_ratio(model_answer_lower, text_lower)

        # Calculate score based on similarity
        if similarity_score >= 80:
            score = weight
        elif similarity_score >= 70:
            score = weight * (similarity_score / 100)
        else:
            score = 0

        results.append(
            {
                "model_answer": model_answer,
                "similarity": similarity_score,
                "score": round(score, 2),
                "max_score": weight,
            }
        )
        total_score += score

    return results, round(total_score, 2)


ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}
MAX_ANSWERS = 50


def _detect_file_type(head):
    """Identify the real file type from its magic bytes."""
    if head[:5] == b"%PDF-":
        return "pdf"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if head[:3] == b"\xff\xd8\xff":
        return "jpg"
    return None


@app.route("/upload", methods=["GET"])
def upload_form():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
@limiter.limit("20 per hour")
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = os.path.basename(file.filename or "")
    if not filename or "." not in filename:
        return jsonify({"error": "Unsupported file type"}), 400
    file_type = filename.rsplit(".", 1)[-1].lower()
    if file_type not in ALLOWED_EXTENSIONS:
        return jsonify({"error": "Unsupported file type"}), 400

    file_bytes = file.read()
    if not file_bytes:
        return jsonify({"error": "The uploaded file is empty"}), 400

    # Trust the bytes, not the extension: reject files whose content does not
    # match a permitted format.
    detected = _detect_file_type(file_bytes[:16])
    expected = "jpg" if file_type in ("jpg", "jpeg") else file_type
    if detected is None or detected != expected:
        return jsonify({"error": "File content does not match its extension"}), 400

    force_ocr = request.form.get("force_ocr", "false").lower() == "true"

    model_answers = [a.strip() for a in request.form.getlist("answers")]
    model_answers = [a for a in model_answers if a]
    raw_weights = request.form.getlist("weights")

    if not model_answers or not raw_weights:
        return jsonify({"error": "Both answers and weights are required"}), 400
    if len(model_answers) != len(raw_weights):
        return jsonify({"error": "answers and weights count must match"}), 400
    if len(model_answers) > MAX_ANSWERS:
        return jsonify({"error": "Too many answers (maximum {})".format(MAX_ANSWERS)}), 400
    if any(len(a) > 2000 for a in model_answers):
        return jsonify({"error": "Each model answer must be 2000 characters or fewer"}), 400

    try:
        weights = [float(w) for w in raw_weights]
    except (TypeError, ValueError):
        return jsonify({"error": "Weights must be numeric values"}), 400
    if any((not math.isfinite(w)) or w < 0 or w > 1000 for w in weights):
        return jsonify({"error": "Weights must be between 0 and 1000"}), 400

    try:
        extraction_result = extract_text(file_bytes, expected, force_ocr=force_ocr)
    except RuntimeError as e:
        app.logger.warning("OCR unavailable: %s", e)
        return jsonify({"error": "Text extraction is unavailable right now"}), 500
    except Exception:
        app.logger.exception("Text extraction failed")
        return jsonify({"error": "Text extraction failed"}), 500

    extracted_text = extraction_result["extracted_text"]
    results, total_score = grade_answer(extracted_text, model_answers, weights)

    try:
        methods = ",".join(
            {detail["method"] for detail in extraction_result["page_details"]}
        )
        record = GradingRecord(
            filename=filename[:255],
            page_count=extraction_result["page_count"],
            total_score=total_score,
            max_score=sum(weights),
            methods=methods,
            extracted_text=extracted_text,
            results=json.dumps(results),
        )
        db.session.add(record)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Failed to save grading record")

    return jsonify(
        {
            "extracted_text": extracted_text,
            "page_count": extraction_result["page_count"],
            "page_details": extraction_result["page_details"],
            "results": results,
            "total_score": total_score,
        }
    )


@app.route("/api/history", methods=["GET"])
@token_required
@limiter.limit("60 per minute")
def history(current_user):
    records = (
        GradingRecord.query.order_by(GradingRecord.created_at.desc()).limit(50).all()
    )
    return (
        jsonify(
            {
                "records": [
                    {
                        "id": record.id,
                        "filename": record.filename,
                        "page_count": record.page_count,
                        "total_score": record.total_score,
                        "max_score": record.max_score,
                        "methods": record.methods,
                        "created_at": record.created_at.strftime("%Y-%m-%d %H:%M")
                        if record.created_at
                        else "",
                    }
                    for record in records
                ]
            }
        ),
        200,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(
        debug=DEBUG,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )
