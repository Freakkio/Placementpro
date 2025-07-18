from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key'  # Change this to something random
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tracker.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    applications = db.relationship('Application', backref='applicant', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    is_eligible = db.Column(db.Boolean, default=False)
    has_applied = db.Column(db.Boolean, default=False)
    company = db.relationship('Company')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class CompanyForm(FlaskForm):
    name = StringField('Company Name', validators=[DataRequired()])
    submit = SubmitField('Add Company')

# --- Routes ---
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    companies = Company.query.all()
    user_applications = Application.query.filter_by(user_id=current_user.id).all()
    
    # Create a dictionary for quick lookup of a user's application status for each company
    user_app_status = {app.company_id: app for app in user_applications}
    
    # Calculate the number of missed applications
    missed_opportunities = 0
    for company in companies:
        app_status = user_app_status.get(company.id)
        if app_status and app_status.is_eligible and not app_status.has_applied:
            missed_opportunities += 1

    return render_template('dashboard.html', companies=companies, user_app_status=user_app_status, missed_opportunities=missed_opportunities)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data)
        user.set_password(form.password.data)
        # The first user to register becomes the admin
        if not User.query.first():
            user.is_admin = True
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_company', methods=['GET', 'POST'])
@login_required
def add_company():
    form = CompanyForm()
    if form.validate_on_submit():
        company = Company(name=form.name.data)
        db.session.add(company)
        db.session.commit()
        flash('Company has been added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_company.html', title='Add Company', form=form)

@app.route('/update_status/<int:company_id>', methods=['POST'])
@login_required
def update_status(company_id):
    is_eligible = request.form.get('eligible') == 'on'
    has_applied = request.form.get('applied') == 'on'
    
    application = Application.query.filter_by(user_id=current_user.id, company_id=company_id).first()
    
    if not application:
        application = Application(user_id=current_user.id, company_id=company_id)
        db.session.add(application)
        
    application.is_eligible = is_eligible
    application.has_applied = has_applied
    
    db.session.commit()
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)