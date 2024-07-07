from flask import Flask, render_template, url_for, flash, redirect, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'streak'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///streak.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(256), nullable=False)
    gems = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Streak(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    streak_type = db.Column(db.String(150), nullable=False)
    count = db.Column(db.Integer, default=0)
    active_days = db.Column(db.String, default='')
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StreakForm(FlaskForm):
    streak_type = StringField('Enter the Activity Of Which You Wish to Make Streak Of', validators=[DataRequired()])
    submit = SubmitField('Create Streak')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    streaks = Streak.query.filter_by(user_id=current_user.id).all()
    current_user.gems = sum(streak.count for streak in streaks)
    db.session.commit()
    return render_template('dashboard.html', streaks=streaks, gems=current_user.gems)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/add_streak', methods=['GET', 'POST'])
@login_required
def add_streak():
    form = StreakForm()
    if form.validate_on_submit():
        streak_type = form.streak_type.data
        new_streak = Streak(user_id=current_user.id, streak_type=streak_type)
        db.session.add(new_streak)
        db.session.commit()
        flash('Streak added successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_streak.html', form=form)

@app.route('/increment_streak/<int:id>')
@login_required
def increment_streak(id):
    streak = Streak.query.get_or_404(id)
    if streak.user_id != current_user.id:
        flash('You can only increment your own streaks.', 'danger')
        return redirect(url_for('dashboard'))

    now = datetime.utcnow()
    
    # Check if the last update was today
    if streak.last_updated.date() == now.date():
        flash('You can only increment this streak once per day.', 'warning')
    else:
        days_since_last_update = (now - streak.last_updated).days

        if days_since_last_update > 1:
            streak.count = 1  # Reset the streak if more than one day has passed
        else:
            streak.count += 1
        
        streak.last_updated = now
        db.session.commit()
        flash('Streak incremented successfully!', 'success')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_streak/<int:id>', methods=['POST'])
@login_required
def delete_streak(id):
    streak = Streak.query.get_or_404(id)
    if streak.user_id != current_user.id:
        return jsonify({'message': 'You can only delete your own streaks'}), 403

    db.session.delete(streak)
    db.session.commit()
    return jsonify({'message': 'Streak deleted successfully'})

@app.route('/dbbackup', methods=['GET'])
def dbbackup():
    return send_from_directory(directory='instance', path='streak.db', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
