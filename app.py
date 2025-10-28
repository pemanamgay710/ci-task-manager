import os
from flask import Flask, render_template, redirect, url_for, flash, request
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_mail import Mail, Message

# import models and forms
from models import db, User, Task
from forms import RegistrationForm, LoginForm, TaskForm, ForgotForm, ResetForm

# Simple global state (no sessions)
current_user_id = None


def create_app(test_config=None):
    app = Flask(__name__, static_folder='static', template_folder='templates')

    # --- Basic config ---
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE', 'sqlite:///app.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # --- Email config ---
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_email_password')
    app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

    # Init extensions
    db.init_app(app)
    CSRFProtect(app)
    mail = Mail(app)
    ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    # Create DB if not testing
    if not app.config.get('TESTING', False):
        with app.app_context():
            db.create_all()

    # ==================== ROUTES ==================== #

    @app.route('/')
    def index():
        global current_user_id
        user = User.query.get(current_user_id) if current_user_id else None
        return render_template('index.html', current_user=user)

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
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    # ---------- Login ----------
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        global current_user_id
        form = LoginForm()
        if form.validate_on_submit():
            user = User.query.filter_by(username=form.username.data).first()
            if user and user.check_password(form.password.data):
                current_user_id = user.id
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            flash('Invalid username or password', 'danger')
        return render_template('login.html', form=form)

    # ---------- Logout ----------
    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        global current_user_id
        current_user_id = None
        flash('Logged out successfully.', 'info')
        return redirect(url_for('index'))


    # ---------- Dashboard ----------
    @app.route('/dashboard', methods=['GET', 'POST'])
    def dashboard():
        global current_user_id
        if not current_user_id:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))

        form = TaskForm()
        user = User.query.get(current_user_id)

        if form.validate_on_submit():
            task = Task(title=form.title.data, user_id=user.id)
            db.session.add(task)
            db.session.commit()
            flash('Task added successfully!', 'success')
            return redirect(url_for('dashboard'))

        tasks = Task.query.filter_by(user_id=user.id).all()
        return render_template('dashboard.html', tasks=tasks, form=form, current_user=user)

    # ---------- Delete Task ----------
    @app.route('/task/delete/<int:task_id>', methods=['POST'])
    def delete_task(task_id):
        global current_user_id
        if not current_user_id:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))

        task = Task.query.get(task_id)
        if not task or task.user_id != current_user_id:
            flash('Not authorized.', 'danger')
            return redirect(url_for('dashboard'))

        db.session.delete(task)
        db.session.commit()
        flash('Task deleted.', 'info')
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
                    msg.body = f"Click to reset your password: {reset_url}"
                    mail.send(msg)
                    flash('Password reset email sent!', 'info')
                except Exception as e:
                    print("Email failed:", e)
                    flash('Email sending failed. Check console.', 'warning')
                    print("Manual reset link:", reset_url)
            else:
                flash('No user with that email.', 'danger')
        return render_template('forgot.html', form=form)

    # ---------- Reset Password ----------
    @app.route('/reset/<token>', methods=['GET', 'POST'])
    def reset_with_token(token):
        try:
            email = ts.loads(token, salt='recover-key', max_age=3600)
        except Exception:
            flash('Invalid or expired reset link.', 'danger')
            return redirect(url_for('forgot'))

        form = ResetForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=email).first()
            if user:
                user.password_hash = generate_password_hash(form.password.data)
                db.session.commit()
                flash('Password updated! Please log in.', 'success')
                return redirect(url_for('login'))
        return render_template('reset.html', form=form)

    return app


# ---------- Run ----------
if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
