#!/usr/bin/python3
from flask import Flask, render_template, redirect, flash, url_for, jsonify, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo
from flask_bcrypt import Bcrypt
import os
from models import User  # Import your User model from models.py
from database import session as db_session  # Import your database session
from forms import RegisterForm, LoginForm

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure SQLAlchemy database URI using environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db_session.query(User).get(int(user_id))

# Routes and views
@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/sign-up', methods=['GET', 'POST'])
def sign():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_customer = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db_session.add(new_customer)
        db_session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))
    return render_template('sign-up.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        customer = db_session.query(User).filter_by(email=form.email.data).first()
        if customer and bcrypt.check_password_hash(customer.password, form.password.data):
            login_user(customer)
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    return render_template('log-in.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
