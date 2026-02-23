import os
import secrets
import io
import logging
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect, url_for,
                   flash, make_response, jsonify, Response, abort, session)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user,
                         login_required, logout_user, current_user)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from openai import OpenAI
from PIL import Image as PILImage

# ----------------------
# Load .env
# ----------------------
load_dotenv()

# ----------------------
# Logging
# ----------------------
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger(__name__)

# ----------------------
# Flask setup
# ----------------------
app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be set in .env and be at least 32 characters.")

# Fix Render's postgres:// → postgresql://
db_url = os.getenv("DATABASE_URL", "")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

# Session / Cookie security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['WTF_CSRF_TIME_LIMIT'] = 3600

# ----------------------
# Extensions
# ----------------------
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'

# ----------------------
# Security headers
# ----------------------
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['X-XSS-Protection']        = '1; mode=block'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']      = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
        "font-src 'self' cdn.jsdelivr.net; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response

# ----------------------
# Brute-force protection
# ----------------------
_login_attempts: dict = {}

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES    = 15

def _get_client_ip() -> str:
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()

def _is_locked_out(ip: str) -> bool:
    entry = _login_attempts.get(ip)
    if not entry:
        return False
    if entry['locked_until'] and datetime.utcnow() < entry['locked_until']:
        return True
    if entry['locked_until'] and datetime.utcnow() >= entry['locked_until']:
        _login_attempts.pop(ip, None)
    return False

def _record_failed_attempt(ip: str):
    entry = _login_attempts.setdefault(ip, {'count': 0, 'locked_until': None})
    entry['count'] += 1
    if entry['count'] >= MAX_LOGIN_ATTEMPTS:
        entry['locked_until'] = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        logger.warning("IP %s locked out after %d failed login attempts.", ip, entry['count'])

def _clear_attempts(ip: str):
    _login_attempts.pop(ip, None)

# ----------------------
# Input validation
# ----------------------
ALLOWED_MODES          = {'b', 'm', 'q', 'c', 'd'}
MAX_QUESTION_LENGTH    = 4000
MAX_IMAGES_PER_REQUEST = 5
ALLOWED_IMAGE_PREFIXES = (
    'data:image/png;base64,',
    'data:image/jpeg;base64,',
    'data:image/jpg;base64,',
    'data:image/webp;base64,',
)

def _validate_base64_image(data: str) -> bool:
    return isinstance(data, str) and any(data.startswith(p) for p in ALLOWED_IMAGE_PREFIXES)

# ----------------------
# WTForms
# ----------------------
class LoginForm(FlaskForm):
    email    = StringField('Email',    validators=[DataRequired(), Length(max=100)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=200)])

# ----------------------
# Models
# ----------------------
class Login_Info(UserMixin, db.Model):
    __tablename__ = 'login_info'
    id           = db.Column(db.Integer, primary_key=True)
    email        = db.Column(db.String(100), unique=True, nullable=False)
    password     = db.Column(db.String(200), nullable=False)
    device_token = db.Column(db.String(200), nullable=True)
    images       = db.relationship('Image', backref='user', lazy=True)

class Image(db.Model):
    __tablename__ = 'image'
    id       = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    data     = db.Column(db.LargeBinary, nullable=False)
    mimetype = db.Column(db.String(50),  nullable=False)
    user_id  = db.Column(db.Integer, db.ForeignKey('login_info.id'), nullable=False)

# ----------------------
# User loader
# ----------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Login_Info, int(user_id))

# ----------------------
# Utility
# ----------------------
def generate_device_token() -> str:
    return secrets.token_urlsafe(32)

# ----------------------
# System prompts
# ----------------------
SYSTEM_PROMPTS = {
    'b': (
        'You are a banking and finance exam assistant. '
        'The user may send text or an image of a question. '
        'Reply with only the final answer — a number, term, or short phrase. '
        'No explanation, no working, no extra text. '
        'If the question has options (A/B/C/D), state only the correct option letter and its text.'
    ),
    'm': (
        'You are an MCQ exam assistant. '
        'The user may send text or an image of a multiple choice question. '
        'Reply with only the correct option in this exact format: "A. answer text". '
        'Never explain. Never add extra text. If multiple answers are correct, list each on a new line.'
    ),
    'q': (
        'You are a study assistant for university exams. '
        'The user may send text or an image of a question. '
        'Give a clear, direct answer. Be concise but complete — include key terms and facts. '
        'No filler phrases like "Great question" or "Certainly". Go straight to the answer.'
    ),

    'c': (
        'You are an expert programming assistant. '
        'The user may send text or an image of a coding problem. '
        'Detect or use the programming language specified in the question. '
        'Common languages include: C#, Python, Java, C++, JavaScript, TypeScript, '
        'SQL, PHP, Swift, Kotlin, Ruby, Go, Rust, and others. '
        'If no language is specified, choose the most appropriate one and clearly state which you used and why. '
    
        # ── MOVE THESE TO THE TOP ──────────────────────────────────────────
        'ABSOLUTE RULES — READ BEFORE DOING ANYTHING ELSE: '
        'Rule 1 — STATIC COUNTER TESTS: '
        '  Never hardcode expected values for static counters. '
        '  Always use this exact pattern: '
        '    int countBefore = ClassName.StaticCounter; '
        '    // perform one action '
        '    Assert.AreEqual(countBefore + 1, ClassName.StaticCounter); '
        '  Reason: static properties accumulate across ALL test methods. '
        '  Hardcoded values will always be wrong when tests run together. '
        '  This rule has NO exceptions. '
    
        'Rule 2 — BOUNDARY VALUE TESTS: '
        '  Always write tests for the EXACT boundary values in the requirements. '
        '  Example: if rule says GPA >= 8, you MUST write: '
        '    - One test with GPA = 8.0 (should pass as High GPA) '
        '    - One test with GPA = 7.99 (should pass as Medium GPA) '
        '    - One test with GPA = 7.0 (should pass as Medium GPA) '
        '    - One test with GPA = 6.99 (should pass as Low GPA) '
        '  Mid-range tests like 8.5 or 7.5 are NOT enough on their own. '
        '  This rule has NO exceptions. '
    
        'Rule 3 — ARRANGE ACT ASSERT: '
        '  Every single test method must have these three comment lines: '
        '    // Arrange '
        '    // Act '
        '    // Assert '
        '  No exceptions. Every test. Every time. '
    
        'Rule 4 — NAMESPACES: '
        '  Every class must be wrapped in a namespace matching the project name. '
        '  Never write a class outside a namespace. '
    
        'Rule 5 — ADD REFERENCE: '
        '  Always include the step to add a project reference from the test project '
        '  to the class library project, or the test project will not compile. '
        # ───────────────────────────────────────────────────────────────────
    
        'STEP 0 — REQUIREMENT ANALYSIS (Do this silently before writing anything): '
        'Read the entire question carefully. '
        'Identify: the programming language, framework, libraries, project type, '
        'all classes, all methods, all properties (including static/shared ones), '
        'all special requirements, all constraints, all expected outputs, '
        'all boundary conditions, and any testing requirements. '
        'Do not skip any requirement no matter how small or implied. '
    
        'ALWAYS follow this exact structure in your response: '
    
        '--- SECTION 1: LANGUAGE, TOOLS & ENVIRONMENT --- '
        'State clearly: '
        '- The programming language being used. '
        '- The IDE or editor recommended. '
        '- The framework or platform if applicable. '
        '- Any libraries or packages required and how to install them. '
    
        '--- SECTION 2: PROJECT & ENVIRONMENT SETUP --- '
        'Provide complete beginner-friendly setup steps including: '
        '- How to create the project or workspace. '
        '- How to add a test project if required. '
        '- How to add a reference from the test project to the class library (Rule 5 above). '
        '- How to configure any build tools or runtime environments. '
        'Adapt steps to the specific language and IDE. Never reuse C# steps for Python. '
    
        '--- SECTION 3: FILE CREATION & CODE --- '
        'For EVERY single file in the solution: '
        '  A) Exact file creation steps for the specific IDE. '
        '  B) Complete code — never truncate, never abbreviate. '
        '  C) Repeat for every file. Never skip. Never merge two files. '
    
        '--- SECTION 4: IMPORTS, LIBRARIES & DEPENDENCIES --- '
        'Show all imports for every file. Remind user of install commands if needed. '
    
        '--- SECTION 5: TESTING --- '
        'Apply ALL 5 ABSOLUTE RULES above when writing tests. '
        'Cover: normal cases, exact boundary values (Rule 2), '
        'static counter with dynamic check (Rule 1), '
        'Arrange/Act/Assert in every test (Rule 3). '
    
        '--- SECTION 6: CODE EXPLANATION --- '
        'Explain every class, method, property in plain English for beginners. '
        'Explain WHY the code is written a certain way. '
        'Never write empty classes or methods with placeholder comments. '
        'Every class must have its complete, working implementation. '
        'If a class inherits from an abstract class, all abstract members '
        'must be overridden with real values — never leave them empty. '
        'If an interface is shown in a class diagram, it must be fully '
        'implemented in the code — never skip interfaces. '
        'For Windows Forms projects, always write the complete '
        'Form1.cs button click handlers AND Form1.Designer.cs '
        'with all controls defined. Never skip form code. '
    
        '--- SECTION 7: EXPECTED OUTPUT & RESULTS --- '
        'Show exact expected output and passing test results. '
    
        '--- SECTION 8: COMPLETENESS CHECK --- '
        'Re-read the original question word by word. '
        'For every class, method, and property — state IMPLEMENTED or MISSING. '
        'Verify all 5 ABSOLUTE RULES were followed in the test file. '
        'If anything is MISSING, write the code immediately. '
        'Never end while anything is MISSING. '
    
        'GLOBAL FORMATTING RULES: '
        'Proper code blocks with correct language tag. '
        'Never compress or shorten code. '
        'Proper indentation and spacing. '
        'Clear headers for every section. '
        'Each file in its own clearly labelled section. '
        'Never truncate — write everything fully. '
        'No placeholder comments like // TODO. '
        'Always write real, working, runnable code. '
    ),

    'd': (
        'You are a system design and diagram assistant. '
        'The user may send text or an image of a diagram or design question. '
        'If asked to explain a diagram: describe each component and how they connect. '
        'If asked to create a diagram: produce a clear ASCII or Mermaid diagram, then explain each part. '
        'Use numbered steps to walk through any process or flow.'
    ),
}

# ----------------------
# Auth routes
# ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        ip = _get_client_ip()

        if _is_locked_out(ip):
            flash('Too many failed attempts. Please try again in 15 minutes.')
            return redirect(url_for('login'))

        user_email = form.email.data.strip()
        password   = form.password.data

        user = Login_Info.query.filter_by(email=user_email).first()

        # Constant-time check to prevent timing attacks
        dummy_hash  = 'pbkdf2:sha256:260000$placeholder$' + 'a' * 64
        stored_hash = user.password if user else dummy_hash
        password_ok = check_password_hash(stored_hash, password)

        if not user or not password_ok:
            _record_failed_attempt(ip)
            flash('Invalid credentials.')
            logger.warning("Failed login for email='%s' from IP=%s", user_email, ip)
            return redirect(url_for('login'))

        # Device restriction
        device_cookie = request.cookies.get('device_token')
        if user.device_token:
            if not secrets.compare_digest(device_cookie or '', user.device_token):
                _record_failed_attempt(ip)
                flash('Access denied: unrecognised device.')
                logger.warning("Device mismatch for user id=%s from IP=%s", user.id, ip)
                return redirect(url_for('login'))
        else:
            token = generate_device_token()
            user.device_token = token
            db.session.commit()
            device_cookie = token

        _clear_attempts(ip)
        login_user(user, remember=False)
        session.permanent = True

        resp = make_response(redirect(url_for('index')))
        resp.set_cookie(
            'device_token',
            device_cookie,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite='Strict',
            secure=True
        )
        return resp

    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/reset_device/<int:user_id>', methods=['POST'])
@login_required
def reset_device(user_id):
    if current_user.id != user_id:
        abort(403)
    user = db.session.get(Login_Info, user_id)
    if not user:
        abort(404)
    user.device_token = None
    db.session.commit()
    logout_user()
    session.clear()
    flash('Device reset. Please log in again.')
    return redirect(url_for('login'))


@app.route('/create_users')
def create_users():
    if os.getenv('ALLOW_CREATE_USERS') != 'true':
        abort(404)
    emails    = ['EaglE!23456789)', 'quilnash', 'dorfem', 'blaenik']
    passwords = ['EaglE!23456789)', 'Bq7!nW4r', 'Tz3@vY8s', 'Pk6$jH1w']
    for email, pwd in zip(emails, passwords):
        if not Login_Info.query.filter_by(email=email).first():
            user = Login_Info(
                email=email,
                password=generate_password_hash(pwd, method='pbkdf2:sha256', salt_length=16),
            )
            db.session.add(user)
    db.session.commit()
    return 'Users created. Set ALLOW_CREATE_USERS=false in your environment now.'

# ----------------------
# Image routes
# ----------------------
@app.route('/')
@login_required
def index():
    images = Image.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', images=images)


@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'image' not in request.files:
        return jsonify({'error': 'No file selected'}), 400

    file = request.files['image']
    if not file or file.filename == '':
        return jsonify({'error': 'No filename'}), 400

    allowed_mimetypes = {'image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/gif'}
    if file.mimetype not in allowed_mimetypes:
        return jsonify({'error': 'File type not allowed'}), 400

    filename = secure_filename(file.filename)
    if not filename:
        return jsonify({'error': 'Invalid filename'}), 400

    try:
        img = PILImage.open(file.stream)
        img.verify()
    except Exception:
        return jsonify({'error': 'Invalid or corrupt image'}), 400

    try:
        file.stream.seek(0)
        img = PILImage.open(file.stream)
        clean = PILImage.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        output = io.BytesIO()
        clean.save(output, format='PNG', optimize=True)
        data = output.getvalue()
    except Exception as e:
        logger.error("Image processing error: %s", e)
        return jsonify({'error': 'Image processing failed'}), 400

    new_image = Image(filename=filename, data=data,
                      mimetype='image/png', user_id=current_user.id)
    db.session.add(new_image)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete/<int:image_id>', methods=['POST'])
@login_required
def delete(image_id):
    image = db.session.get(Image, image_id)
    if not image:
        abort(404)
    if image.user_id != current_user.id:
        abort(403)
    db.session.delete(image)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/image/<int:image_id>')
@login_required
def get_image(image_id):
    image = db.session.get(Image, image_id)
    if not image:
        abort(404)
    if image.user_id != current_user.id:
        abort(403)
    resp = Response(image.data, mimetype=image.mimetype)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

# ----------------------
# AI Chat
# ----------------------
import os
from flask import Flask, request, jsonify
from openai import OpenAI
import anthropic

@app.route('/ask', methods=['POST'])
@login_required
def ask():
    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, dict):
        return jsonify({'answer': 'Invalid request.'}), 400

    question = payload.get('question', '')
    images   = payload.get('images', [])
    mode     = payload.get('mode', 'q')

    if mode not in ALLOWED_MODES:
        mode = 'q'

    if not isinstance(question, str) or not question.strip():
        return jsonify({'answer': 'Please enter a question.'}), 400
    if len(question) > MAX_QUESTION_LENGTH:
        return jsonify({'answer': 'Question is too long.'}), 400

    if not isinstance(images, list):
        return jsonify({'answer': 'Invalid images format.'}), 400
    if len(images) > MAX_IMAGES_PER_REQUEST:
        return jsonify({'answer': f'Maximum {MAX_IMAGES_PER_REQUEST} images allowed.'}), 400
    for img in images:
        if not _validate_base64_image(img):
            return jsonify({'answer': 'Invalid image data.'}), 400

    system_prompt = SYSTEM_PROMPTS[mode]

    # ── ROUTE: Claude for code, GPT for everything else ──────────────
    if mode == 'c':
        answer = _ask_claude(system_prompt, question, images)
    else:
        answer = _ask_gpt(system_prompt, question, images, mode)

    return jsonify({'answer': answer})


def _ask_claude(system_prompt, question, images):
    """Claude API — used for code mode only."""
    try:
        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))

        # Build content — text + optional images
        if images:
            content = [{'type': 'text', 'text': question.strip()}]
            for img_data in images:
                # Strip base64 header: "data:image/jpeg;base64,xxxx"
                if ',' in img_data:
                    header, data = img_data.split(',', 1)
                    # Detect media type from header
                    if 'jpeg' in header or 'jpg' in header:
                        media_type = 'image/jpeg'
                    elif 'png' in header:
                        media_type = 'image/png'
                    elif 'gif' in header:
                        media_type = 'image/gif'
                    elif 'webp' in header:
                        media_type = 'image/webp'
                    else:
                        media_type = 'image/jpeg'  # default fallback
                else:
                    data = img_data
                    media_type = 'image/jpeg'

                content.append({
                    'type': 'image',
                    'source': {
                        'type': 'base64',
                        'media_type': media_type,
                        'data': data
                    }
                })
        else:
            content = question.strip()

        response = client.messages.create(
            model='claude-sonnet-4-6',   # Best for code
            max_tokens=12000,
            system=system_prompt,
            messages=[{'role': 'user', 'content': content}]
        )

        return response.content[0].text

    except Exception as e:
        logger.error("Claude API error: %s", e)
        return 'An error occurred with Claude. Please try again.'


def _ask_gpt(system_prompt, question, images, mode):
    """GPT-4o API — used for all non-code modes."""
    try:
        client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        # Token + temperature settings per mode
        if mode == 'd':
            max_tokens  = 6000
            temperature = 0.3
        else:
            max_tokens  = 1024
            temperature = 0.7

        messages = [{'role': 'system', 'content': system_prompt}]

        if images:
            content = [{'type': 'text', 'text': question.strip()}]
            for img_data in images:
                content.append({
                    'type': 'image_url',
                    'image_url': {'url': img_data}
                })
            messages.append({'role': 'user', 'content': content})
        else:
            messages.append({'role': 'user', 'content': question.strip()})

        response = client.chat.completions.create(
            model='gpt-4o',
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=0.95,
        )

        return response.choices[0].message.content

    except Exception as e:
        logger.error("GPT API error: %s", e)
        return 'An error occurred with GPT. Please try again.'

# ----------------------
# Error handlers
# ----------------------
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 5 MB)'}), 413

@app.errorhandler(500)
def server_error(e):
    logger.error("Unhandled server error: %s", e)
    return jsonify({'error': 'Internal server error'}), 500

# ----------------------
# Run
# ----------------------
# Create tables on every startup (safe — skips existing tables)
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))