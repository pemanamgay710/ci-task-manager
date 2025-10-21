from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db_init, User, Task, get_db_session
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegistrationForm, LoginForm, TaskForm
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')
app.config['DATABASE'] = 'app.db'

# initialize DB
db_init(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    session = get_db_session()
    return session.query(User).get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        session = get_db_session()
        existing = session.query(User).filter_by(username=form.username.data).first()
        if existing:
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))
        hashed = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed)
        session.add(user)
        session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = get_db_session()
        user = session.query(User).filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = TaskForm()
    session = get_db_session()
    if form.validate_on_submit():
        task = Task(title=form.title.data, user_id=current_user.id)
        session.add(task)
        session.commit()
        flash('Task added', 'success')
        return redirect(url_for('dashboard'))
    tasks = session.query(Task).filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', tasks=tasks, form=form)

@app.route('/task/delete/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    session = get_db_session()
    task = session.query(Task).get(task_id)
    if task and task.user_id == current_user.id:
        session.delete(task)
        session.commit()
        flash('Task deleted', 'info')
    else:
        flash('Not allowed', 'danger')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)