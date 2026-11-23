import os
import re
import secrets
from datetime import datetime, timezone

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-key')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local_dev.db')
if db_url.startswith('postgres://'):
    db_url = db_url.replace('postgres://', 'postgresql+psycopg://', 1)
elif db_url.startswith('postgresql://'):
    db_url = db_url.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('RENDER', '') == 'true'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    presets = db.relationship('Preset', backref='owner', cascade='all, delete-orphan', lazy=True)


class Preset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    preset_key = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    state = db.Column(db.JSON, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'preset_key', name='uq_user_preset_key'),)


def csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']


@app.context_processor
def inject_helpers():
    return {'csrf_token': csrf_token}


@app.before_request
def protect_state_changes():
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        supplied = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
        expected = session.get('_csrf_token')
        if not expected or not supplied or not secrets.compare_digest(supplied, expected):
            abort(400, description='בקשה לא תקינה. רענן את הדף ונסה שוב.')


def current_user():
    user_id = session.get('user_id')
    return db.session.get(User, user_id) if user_id else None


def login_required(view):
    from functools import wraps
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            if request.path.startswith('/api/'):
                return jsonify(error='נדרשת התחברות מחדש'), 401
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped


@app.get('/')
def home():
    user = current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('calculator.html', current_user_email=user.email)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user():
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            flash('כתובת המייל אינה תקינה.', 'error')
        elif len(password) < 8:
            flash('הסיסמה חייבת להכיל לפחות 8 תווים.', 'error')
        elif User.query.filter(func.lower(User.email) == email).first():
            flash('כבר קיים חשבון עם כתובת המייל הזאת.', 'error')
        else:
            user = User(email=email, password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session.clear()
            session['user_id'] = user.id
            csrf_token()
            return redirect(url_for('home'))
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user():
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        user = User.query.filter(func.lower(User.email) == email).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session['user_id'] = user.id
            csrf_token()
            return redirect(url_for('home'))
        flash('כתובת המייל או הסיסמה אינן נכונות.', 'error')
    return render_template('auth.html', mode='login')


@app.post('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/api/presets', methods=['GET', 'PUT'])
@login_required
def user_presets():
    user = current_user()
    if request.method == 'GET':
        rows = Preset.query.filter_by(user_id=user.id).order_by(Preset.updated_at.desc()).all()
        return jsonify(presets=[{'id': p.preset_key, 'name': p.name, 'state': p.state} for p in rows])

    payload = request.get_json(silent=True)
    if not isinstance(payload, list) or len(payload) > 100:
        return jsonify(error='מבנה התמהילים אינו תקין (עד 100 תמהילים).'), 400

    cleaned = []
    seen = set()
    for item in payload:
        if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not isinstance(item.get('name'), str) or not isinstance(item.get('state'), dict):
            return jsonify(error='אחד התמהילים מכיל נתונים לא תקינים.'), 400
        key = item['id'][:100]
        name = item['name'].strip()[:120]
        if not key or not name or key in seen:
            return jsonify(error='נמצא תמהיל ללא שם או עם מזהה כפול.'), 400
        seen.add(key)
        cleaned.append((key, name, item['state']))

    # Replace only this user's collection; other users' records are never touched.
    Preset.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    for key, name, state in cleaned:
        db.session.add(Preset(user_id=user.id, preset_key=key, name=name, state=state))
    db.session.commit()
    return jsonify(ok=True, count=len(cleaned))


@app.get('/health')
def health():
    return {'status': 'ok'}


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
