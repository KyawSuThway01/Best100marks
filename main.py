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
import anthropic

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
# AWS Diagram Generator
# ----------------------
def generate_aws_diagram():
    """Generate AWS architecture diagram and return as base64 PNG string."""
    from PIL import Image as PilImg, ImageDraw, ImageFont
    import math
    import base64

    W, H = 1400, 900
    img = PilImg.new("RGB", (W, H), "#1a1a2e")
    draw = ImageDraw.Draw(img)

    try:
        font_title = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 26)
        font_label = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 15)
        font_small = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 12)
        font_arrow = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 11)
        font_tiny  = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 10)
    except Exception:
        font_title = ImageFont.load_default()
        font_label = font_title
        font_small = font_title
        font_arrow = font_title
        font_tiny  = font_title

    CARD  = "#16213e"
    BORDER= "#0f3460"
    WHITE = "#ffffff"
    GRAY  = "#90a4ae"
    ARROW = "#546e7a"
    LBLBG = "#0d1b2a"

    colors = {
        "user":    "#4fc3f7",
        "route53": "#8C4FFF",
        "cf":      "#FF9900",
        "s3":      "#3F8624",
        "waf":     "#DD344C",
        "apigw":   "#4a90d9",
        "cognito": "#BF0816",
        "lambda":  "#FF6600",
        "dynamo":  "#6B3FA0",
        "sqs":     "#D4AC0D",
        "sns":     "#E91E8C",
        "cw":      "#00897B",
    }

    def draw_card(x, y, w, h, color, label, sublabel="", icon=""):
        draw.rounded_rectangle([x+4, y+4, x+w+4, y+h+4], radius=10, fill="#0a0a1a")
        draw.rounded_rectangle([x, y, x+w, y+h], radius=10, fill=CARD, outline=color, width=2)
        draw.rounded_rectangle([x, y, x+w, y+18], radius=10, fill=color)
        draw.rectangle([x, y+9, x+w, y+18], fill=color)
        if icon:
            draw.text((x+w//2, y+36), icon, fill=color, font=font_label, anchor="mm")
        draw.text((x+w//2, y+55), label, fill=WHITE, font=font_label, anchor="mm")
        if sublabel:
            draw.text((x+w//2, y+70), sublabel, fill=GRAY, font=font_tiny, anchor="mm")

    def arrow(x1, y1, x2, y2, label="", color=ARROW, dashed=False):
        if dashed:
            dist  = math.hypot(x2-x1, y2-y1)
            steps = max(int(dist/12), 1)
            for i in range(steps):
                if i % 2 == 0:
                    t1 = i / steps
                    t2 = min((i+0.5) / steps, 1.0)
                    draw.line([x1+(x2-x1)*t1, y1+(y2-y1)*t1,
                               x1+(x2-x1)*t2, y1+(y2-y1)*t2], fill=color, width=1)
        else:
            draw.line([x1, y1, x2, y2], fill=color, width=2)
        ang = math.atan2(y2-y1, x2-x1)
        sz  = 9
        draw.polygon([
            (x2, y2),
            (x2 - sz*math.cos(ang-0.4), y2 - sz*math.sin(ang-0.4)),
            (x2 - sz*math.cos(ang+0.4), y2 - sz*math.sin(ang+0.4))
        ], fill=color)
        if label:
            mx, my = (x1+x2)//2, (y1+y2)//2
            tw = len(label)*6 + 8
            draw.rounded_rectangle([mx-tw//2, my-9, mx+tw//2, my+9], radius=3, fill=LBLBG, outline=BORDER)
            draw.text((mx, my), label, fill=GRAY, font=font_arrow, anchor="mm")

    # Title
    draw.text((W//2, 36), "AWS Serverless Web Application Architecture",
              fill=WHITE, font=font_title, anchor="mm")
    draw.line([80, 56, W-80, 56], fill=BORDER, width=1)

    # AWS Region box
    draw.rounded_rectangle([75, 65, W-75, H-45], radius=14, outline=BORDER, width=2)
    draw.text((108, 78), "AWS Region: us-east-1", fill=GRAY, font=font_small)

    CW, CH = 118, 88

    nodes = {
        "user":    (95,  420, 100, 84),
        "route53": (240, 420, CW,  CH),
        "cf":      (415, 260, CW,  CH),
        "s3":      (415, 130, CW,  CH),
        "waf":     (590, 260, CW,  CH),
        "apigw":   (765, 260, CW,  CH),
        "cognito": (765, 130, CW,  CH),
        "lambda":  (940, 260, CW,  CH),
        "dynamo":  (1115,160, CW,  CH),
        "sqs":     (1115,340, CW,  CH),
        "sns":     (1115,500, CW,  CH),
        "cw":      (300, 640, 800, 72),
    }

    def cx(n): return nodes[n][0] + nodes[n][2]//2
    def cy(n): return nodes[n][1] + nodes[n][3]//2
    def R(n):  return nodes[n][0] + nodes[n][2]
    def L(n):  return nodes[n][0]
    def T(n):  return nodes[n][1]
    def B(n):  return nodes[n][1] + nodes[n][3]

    # Draw arrows
    arrow(R("user"),    cy("user"),       L("route53"), cy("route53"),    "HTTPS")
    arrow(R("route53"), cy("route53"),    L("cf"),      cy("cf"),         "Routes Traffic")
    arrow(cx("cf"),     T("cf"),          cx("s3"),     B("s3"),          "Static Assets")
    arrow(R("cf"),      cy("cf"),         L("waf"),     cy("waf"),        "Forward")
    arrow(R("waf"),     cy("waf"),        L("apigw"),   cy("apigw"),      "Filtered Req")
    arrow(cx("apigw"),  T("apigw"),       cx("cognito"),B("cognito"),     "Validate JWT")
    arrow(R("apigw"),   cy("apigw"),      L("lambda"),  cy("lambda"),     "Invoke")
    arrow(R("lambda"),  cy("lambda")-18,  L("dynamo"),  cy("dynamo"),     "Read/Write")
    arrow(R("lambda"),  cy("lambda")+18,  L("sqs"),     cy("sqs"),        "Queue Task")
    arrow(cx("sqs"),    B("sqs"),         cx("sns"),    T("sns"),         "Trigger")
    arrow(cx("cw"),     T("cw"),          cx("lambda"), B("lambda"),      "Logs",  "#00897B", dashed=True)
    arrow(L("cw")+60,   T("cw"),          cx("apigw"),  B("apigw"),       "",      "#00897B", dashed=True)

    # Draw service cards
    x, y, w, h = nodes["user"]
    draw.rounded_rectangle([x+4, y+4, x+w+4, y+h+4], radius=10, fill="#0a0a1a")
    draw.rounded_rectangle([x, y, x+w, y+h], radius=10, fill="#1e3a5f", outline=colors["user"], width=2)
    draw.text((x+w//2, y+28), "U",    fill=colors["user"], font=font_label, anchor="mm")
    draw.text((x+w//2, y+52), "User", fill=WHITE,          font=font_label, anchor="mm")
    draw.text((x+w//2, y+67), "Browser", fill=GRAY,        font=font_tiny,  anchor="mm")

    draw_card(*nodes["route53"], colors["route53"], "Route 53",   "DNS",       "R53")
    draw_card(*nodes["cf"],      colors["cf"],      "CloudFront", "CDN",       "CF")
    draw_card(*nodes["s3"],      colors["s3"],      "Amazon S3",  "Storage",   "S3")
    draw_card(*nodes["waf"],     colors["waf"],     "AWS WAF",    "Firewall",  "WAF")
    draw_card(*nodes["apigw"],   colors["apigw"],   "API Gateway","REST API",  "GW")
    draw_card(*nodes["cognito"], colors["cognito"], "Cognito",    "Auth",      "COG")
    draw_card(*nodes["lambda"],  colors["lambda"],  "Lambda",     "Serverless","Fn")
    draw_card(*nodes["dynamo"],  colors["dynamo"],  "DynamoDB",   "NoSQL DB",  "DB")
    draw_card(*nodes["sqs"],     colors["sqs"],     "Amazon SQS", "Queue",     "SQS")
    draw_card(*nodes["sns"],     colors["sns"],     "Amazon SNS", "Notify",    "SNS")

    # CloudWatch wide bar
    x, y, w, h = nodes["cw"]
    draw.rounded_rectangle([x+4, y+4, x+w+4, y+h+4], radius=10, fill="#0a0a1a")
    draw.rounded_rectangle([x, y, x+w, y+h], radius=10, fill=CARD, outline=colors["cw"], width=2)
    draw.rounded_rectangle([x, y, x+w, y+18], radius=10, fill=colors["cw"])
    draw.rectangle([x, y+9, x+w, y+18], fill=colors["cw"])
    draw.text((x+w//2, y+40),
              "Amazon CloudWatch  —  Monitoring & Logging (All Services)",
              fill=WHITE, font=font_label, anchor="mm")

    # Legend
    lx, ly = 90, H-35
    legend = [
        ("■", colors["route53"], "DNS"),
        ("■", colors["cf"],      "CDN"),
        ("■", colors["s3"],      "Storage"),
        ("■", colors["waf"],     "Firewall"),
        ("■", colors["apigw"],   "API"),
        ("■", colors["lambda"],  "Compute"),
        ("■", colors["dynamo"],  "Database"),
        ("■", colors["sqs"],     "Queue"),
        ("■", colors["sns"],     "Notify"),
        ("■", colors["cw"],      "Monitor"),
    ]
    for i, (sym, col, lbl) in enumerate(legend):
        ox = lx + i * 130
        draw.text((ox,    ly), sym, fill=col,  font=font_small)
        draw.text((ox+14, ly), lbl, fill=GRAY, font=font_small)

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")

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
        'You are an expert AWS Solutions Architect and diagram assistant. '
        'When the user asks to draw or create an AWS architecture diagram, always respond in this exact structure: '

        'PART 1 — ARCHITECTURE OVERVIEW: '
        'List all AWS services used and explain the role of each one in one sentence. '

        'PART 2 — ASCII DIAGRAM: '
        'Produce a clean ASCII diagram using box characters (+-|) and arrows (-->, v, /,\\) '
        'showing all components and data flow. Label every arrow. '
        'Layout rule: User on the far left, flow moves left to right, branches go top/bottom from Lambda. '

        'PART 3 — FINISHED DIAGRAM DESCRIPTION: '
        'Describe exactly how the finished professional diagram should look as if it were a real image: '
        'dark background, color-coded service cards (CloudFront=orange, S3=green, API Gateway=blue, '
        'Lambda=red, DynamoDB=purple, Cognito=pink, SQS=yellow, CloudWatch=teal), '
        'directional arrows with labels, AWS Region boundary box, legend at the bottom. '
        'Tell the user they can recreate this in draw.io using AWS17 shape libraries. '

        'PART 4 — STEP-BY-STEP DRAWING INSTRUCTIONS (draw.io): '
        'Give numbered steps: open draw.io, enable AWS17 shape library, '
        'add each service icon in canvas order (left to right), '
        'draw labeled arrows with exact label text for each connection, '
        'style with matching colors per service category, add title and legend, export as PNG. '

        'PART 5 — HAND-DRAWN OPTION: '
        'Repeat the ASCII layout as a drawing guide. Add tips: use ruler, label all boxes, '
        'use colored pens per category, photograph in good lighting, crop before submitting. '

        'PART 6 — SUBMISSION CHECKLIST: '
        'End with a markdown checklist table. '

        'Always use official AWS service names. Keep instructions beginner-friendly and numbered.'
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

    # ── ROUTE: Claude for code and diagrams, GPT for everything else ──
    if mode in ('c', 'd'):
        answer = _ask_claude(system_prompt, question, images, mode)
    else:
        answer = _ask_gpt(system_prompt, question, images, mode)

    # For diagram mode, also generate and return the PNG image
    if mode == 'd':
        try:
            diagram_b64 = generate_aws_diagram()
            return jsonify({'answer': answer, 'diagram': diagram_b64})
        except Exception as e:
            logger.error("Diagram generation error: %s", e)
            return jsonify({'answer': answer})

    return jsonify({'answer': answer})


def _ask_claude(system_prompt, question, images, mode='c'):
    """Claude API — used for code (c) and diagram (d) modes."""
    try:
        client = anthropic.Anthropic(
            api_key=os.getenv('ANTHROPIC_API_KEY'),
            timeout=90.0  # Prevent Gunicorn worker timeout
        )

        # d mode needs fewer tokens than c mode
        max_tok = 6000 if mode == 'd' else 12000

        # Build content — text + optional images
        if images:
            content = [{'type': 'text', 'text': question.strip()}]
            for img_data in images:
                if ',' in img_data:
                    header, data = img_data.split(',', 1)
                    if 'jpeg' in header or 'jpg' in header:
                        media_type = 'image/jpeg'
                    elif 'png' in header:
                        media_type = 'image/png'
                    elif 'gif' in header:
                        media_type = 'image/gif'
                    elif 'webp' in header:
                        media_type = 'image/webp'
                    else:
                        media_type = 'image/jpeg'
                else:
                    data       = img_data
                    media_type = 'image/jpeg'

                content.append({
                    'type': 'image',
                    'source': {
                        'type':       'base64',
                        'media_type': media_type,
                        'data':       data
                    }
                })
        else:
            content = question.strip()

        response = client.messages.create(
            model='claude-sonnet-4-6',
            max_tokens=max_tok,
            system=system_prompt,
            messages=[{'role': 'user', 'content': content}]
        )

        return response.content[0].text

    except Exception as e:
        logger.error("Claude API error: %s", e)
        return 'An error occurred with Claude. Please try again.'


def _ask_gpt(system_prompt, question, images, mode):
    """GPT-4o API — used for all non-code/non-diagram modes."""
    try:
        client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

        max_tokens  = 1024
        temperature = 0.7

        messages = [{'role': 'system', 'content': system_prompt}]

        if images:
            content = [{'type': 'text', 'text': question.strip()}]
            for img_data in images:
                content.append({
                    'type':      'image_url',
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