import os
from datetime import timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, make_response
from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
from flask_jwt_extended import (
    JWTManager, create_access_token, set_access_cookies,
    unset_jwt_cookies, jwt_required, get_jwt_identity, verify_jwt_in_request
)

# Import models and forms
from models import db, User, Task
from forms import RegistrationForm, LoginForm, TaskForm, ForgotForm, ResetForm


def create_app(test_config=None):
    app = Flask(__name__, static_folder='static', template_folder='templates')

    # ------------------ Basic Config ------------------
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ------------------ Email Config ------------------
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

    # ------------------ JWT Config ------------------
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret')
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_SECURE'] = False  # True in production (HTTPS)
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
    app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=20)
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Disable JWT CSRF (we use HTML forms)

    # ------------------ Initialize Extensions ------------------
    db.init_app(app)
    jwt = JWTManager(app)
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        flash("Your session has expired. Please log in again.", "warning")
        resp = make_response(redirect(url_for('login')))
        unset_jwt_cookies(resp)
        return resp

    
    csrf = CSRFProtect(app)  # ✅ Create reference for route exemption
    mail = Mail(app)
    ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # ------------------ Create Database ------------------
    if not app.config.get('TESTING', False):
        with app.app_context():
            db.create_all()

    # ------------------ Context Processor ------------------
    @app.context_processor
    def inject_user():
        """Injects current user into templates if JWT exists."""
        try:
            verify_jwt_in_request(optional=True)
            user_id = get_jwt_identity()
            if user_id:
                user = User.query.get(int(user_id))
                return {'current_user': user}
        except Exception:
            pass
        return {'current_user': None}

    # ------------------ Routes ------------------

    @app.route('/')
    def index():
        return render_template('index.html')

    # ---------- Register ----------
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegistrationForm()
        if form.validate_on_submit():
            existing = User.query.filter(
                (User.username == form.username.data) | (User.email == form.email.data)
            ).first()
            if existing:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))

            hashed_pw = generate_password_hash(form.password.data)
            new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_pw)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    # ---------- Login ----------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                # Convert user ID to string for JWT
                access_token = create_access_token(identity=str(user.id))
                resp = make_response(redirect(url_for('dashboard')))
                set_access_cookies(resp, access_token)
                flash('Logged in successfully!', 'success')
                return resp
            else:
                flash('Invalid username or password.', 'danger')
        return render_template('login.html', form=form)

    # ---------- Logout ----------
    @app.route('/logout')
    def logout():
        resp = make_response(redirect(url_for('index')))
        unset_jwt_cookies(resp)
        flash('Logged out successfully.', 'info')
        return resp

    # ---------- Dashboard ----------
    @app.route('/dashboard', methods=['GET', 'POST'])
    @jwt_required()
    def dashboard():
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        form = TaskForm()

        if form.validate_on_submit():
            task = Task(title=form.title.data, user_id=user.id)
            db.session.add(task)
            db.session.commit()
            flash('Task added successfully!', 'success')
            return redirect(url_for('dashboard'))

        tasks = Task.query.filter_by(user_id=user.id).all()
        return render_template('dashboard.html', tasks=tasks, form=form, current_user=user)

    # ---------- Edit Task ----------
    @app.route('/task/edit/<int:task_id>', methods=['GET', 'POST'])
    @jwt_required()
    def edit_task(task_id):
        user_id = int(get_jwt_identity())
        task = Task.query.get(task_id)
        if not task or task.user_id != user_id:
            flash('Not authorized.', 'danger')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            new_title = request.form.get('new_title')
            if new_title:
                task.title = new_title
                db.session.commit()
                flash('Task updated successfully!', 'success')
                return redirect(url_for('dashboard'))

        return render_template('edit_task.html', task=task)

    # ---------- Delete Task ----------
    @app.route('/task/delete/<int:task_id>', methods=['POST'])
    @jwt_required()
    @csrf.exempt  # ✅ Correct modern way to disable CSRF for this route
    def delete_task(task_id):
        user_id = int(get_jwt_identity())
        task = Task.query.get(task_id)
        if not task or task.user_id != user_id:
            flash('Not authorized.', 'danger')
            return redirect(url_for('dashboard'))

        db.session.delete(task)
        db.session.commit()
        flash('Task deleted successfully!', 'info')
        return redirect(url_for('dashboard'))

    # ---------- Forgot Password ----------
    @app.route('/forgot', methods=['GET', 'POST'])
    def forgot():
        form = ForgotForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                token = ts.dumps(user.email, salt='recover-key')
                reset_url = url_for('reset_with_token', token=token, _external=True)
                try:
                    msg = Message('Password Reset Request', recipients=[user.email])
                    msg.body = f"Click here to reset your password: {reset_url}"
                    mail.send(msg)
                    flash('Password reset link sent to your email.', 'info')
                except Exception as e:
                    print("Email sending failed:", e)
                    flash('Email sending failed. Reset link printed to console.', 'warning')
                    print("Reset URL:", reset_url)
            else:
                flash('No account with that email address.', 'danger')
        return render_template('forgot.html', form=form)

    # ---------- Reset Password ----------
    @app.route('/reset/<token>', methods=['GET', 'POST'])
    def reset_with_token(token):
        try:
            email = ts.loads(token, salt='recover-key', max_age=3600)
        except Exception:
            flash('The reset link is invalid or expired.', 'danger')
            return redirect(url_for('forgot'))

        form = ResetForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=email).first()
            if user:
                user.password_hash = generate_password_hash(form.password.data)
                db.session.commit()
                flash('Password updated successfully!', 'success')
                return redirect(url_for('login'))
        return render_template('reset.html', form=form)

    return app


# ------------------ Run App ------------------
if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
